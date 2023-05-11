#![feature(int_roundings)]

mod structs;
use crate::structs::{BlockGroupDescriptor, DirectoryEntry, Inode, Superblock, TypeIndicator};
use std::mem;
use null_terminated::NulStr;
use uuid::Uuid;
use zerocopy::ByteSlice;
use std::fmt;
use rustyline::{DefaultEditor, Result};
use std::fs;
use std::env::args;

#[repr(C)]
#[derive(Debug)]
pub struct Ext2 {
    pub start_ptr: &'static [u8],
    pub superblock: &'static Superblock,
    pub block_groups: &'static mut [BlockGroupDescriptor],
    pub blocks: Vec<&'static [u8]>,
    pub block_size: usize,
    pub total_size: usize,
    pub uuid: Uuid,
    pub block_offset: usize, // <- our "device data" actually starts at this index'th block of the device
                             // so we have to subtract this number before indexing blocks[]
}

const EXT2_MAGIC: u16 = 0xef53;
const EXT2_START_OF_SUPERBLOCK: usize = 1024;
const EXT2_END_OF_SUPERBLOCK: usize = 2048;

impl Ext2 {
    pub fn new<B: ByteSlice + std::fmt::Debug + std::ops::DerefMut>(device_bytes: &mut B, start_addr: usize) -> Ext2 {
        // https://wiki.osdev.org/Ext2#Superblock
        // parse into Ext2 struct - without copying

        // the superblock goes from bytes 1024 -> 2047
        let mut header_body_bytes = (*device_bytes).split_at_mut(EXT2_END_OF_SUPERBLOCK);

        let mut header_parts = header_body_bytes.0.split_at_mut(EXT2_START_OF_SUPERBLOCK);
  
        let superblock = unsafe {
            &*(header_parts
                .1
                .as_ptr() as *mut Superblock)
        };
        assert_eq!(superblock.magic, EXT2_MAGIC);
        // at this point, we strongly suspect these bytes are indeed an ext2 filesystem

        println!("superblock:\n{:?}", superblock);
        println!("size of Inode struct: {}", mem::size_of::<Inode>());

        let block_group_count = superblock
            .blocks_count
            .div_ceil(superblock.blocks_per_group) as usize;

        let block_size: usize = 1024 << superblock.log_block_size;
        println!(
            "there are {} block groups and block_size = {}",
            block_group_count, block_size
        );
        let block_groups_rest_bytes = header_body_bytes.1.split_at(block_size);

        let block_groups = unsafe {
            std::slice::from_raw_parts_mut(
                block_groups_rest_bytes.0.as_ptr() as *mut BlockGroupDescriptor,
                block_group_count,
            )
        };

        println!("block group 0: {:?}", block_groups[0]);

        let blocks = unsafe {
            std::slice::from_raw_parts(
                block_groups_rest_bytes.1.as_ptr() as *mut u8,
                // would rather use: device_bytes.as_ptr(),
                superblock.blocks_count as usize * block_size,
            )
        }
        .chunks(block_size)
        .collect::<Vec<_>>();

        let offset_bytes = (blocks[0].as_ptr() as usize) - start_addr;
        let block_offset = offset_bytes / block_size;
        let uuid = Uuid::from_bytes(superblock.fs_id);
        
        let total_size = (superblock.blocks_count as usize) * block_size;
        println!("The total size of the file system is {} bytes", total_size);
        let start_ptr = unsafe { std::slice::from_raw_parts_mut(header_parts.0.as_mut_ptr(), total_size) };

        Ext2 {
            start_ptr,
            superblock,
            block_groups,
            blocks,
            block_size,
            total_size,
            uuid,
            block_offset,
        }
    }

    // given a (1-indexed) inode number, return that #'s inode structure
    pub fn get_inode(&self, inode: usize) -> &mut Inode {
        let group: usize = (inode - 1) / self.superblock.inodes_per_group as usize;
        let index: usize = (inode - 1) % self.superblock.inodes_per_group as usize;

        //println!("in get_inode, inode num = {}, index = {}, group = {}", inode, index, group);
        let inode_table_block = (self.block_groups[group].inode_table_block) as usize - self.block_offset;
        // println!("in get_inode, block number of inode table {}", inode_table_block);
        let inode_table: &mut [Inode] = unsafe {
            std::slice::from_raw_parts_mut(
                self.blocks[inode_table_block].as_ptr()
                    as *mut Inode,
                self.superblock.inodes_per_group as usize,
            )
        };
        // probably want a Vec of BlockGroups in our Ext structure so we don't have to slice each time,
        // but this works for now.
        // println!("{:?}", inode_table);
        &mut inode_table[index]
    }

    // given an inode number, parse that inode as a directory and return directory contents
    pub fn read_dir_inode(&self, inode: usize) -> std::io::Result<Vec<(usize, &NulStr)>> {
        let mut ret = Vec::new();
        let root = self.get_inode(inode);
        // println!("in read_dir_inode, #{} : {:?}", inode, root);
        // println!("following direct pointer to data block: {}", root.direct_pointer[0]);
        let entry_ptr = self.blocks[root.direct_pointer[0] as usize - self.block_offset].as_ptr();
        let mut byte_offset: isize = 0;
        while byte_offset < root.size_low as isize { // <- todo, support large directories
            let directory = unsafe { 
                &*(entry_ptr.offset(byte_offset) as *const DirectoryEntry) 
            };
            // println!("{:?}", directory);
            byte_offset += directory.entry_size as isize;
            ret.push((directory.inode as usize, &directory.name));
        } 
        Ok(ret)
    }

    // given a block number, read the contents of that block as an array of bytes
    pub fn read_dir_block(&self, block: usize) -> std::io::Result<&mut [u8]> {
        let size: isize = 1 << (self.superblock.log_block_size + 10);
        let entry_ptr = self.blocks[block - self.block_offset].as_ptr();
        unsafe { Ok(std::slice::from_raw_parts_mut(
            entry_ptr as *mut u8,
            1024 << self.superblock.log_block_size,
        )) }
    }

    // find free inode and allocate it for use, specifically for a directory
    pub fn allocate_inode(&mut self) -> std::result::Result<usize, &str> {
        let mut group_i = 0;
        for group_i in 0..self.block_groups.len() {
            if self.block_groups[group_i].free_inodes_count > 0 {
                break;
            }
        };
        
        let group = &mut self.block_groups[group_i];

        group.free_inodes_count -= 1;
        group.dirs_count += 1; // this only applies to directories

        let inode_bitmap_addr = usize::try_from(group.inode_usage_addr).unwrap();


        let mut inode_bitmap = self.read_dir_block(inode_bitmap_addr).unwrap();
        let mut inode_number = 0;
        for i in 1..self.superblock.inodes_per_group {
            let which_byte = usize::try_from(i / 8).unwrap();
            let which_bit = usize::try_from(i % 8).unwrap();
            // Check if relevant bit is 1 or 0 by ANDing with 1 << which_bit
            if !(inode_bitmap[which_byte] & (1 << which_bit) > 0) {
                // println!("Bitmap before: {}", inode_bitmap[which_byte]);
                inode_number = i+1;
                inode_bitmap[which_byte] = inode_bitmap[which_byte] | (1 << which_bit);
                break
            }
        }
        let bm = self.read_dir_block(usize::try_from(self.block_groups[group_i].inode_usage_addr).unwrap()).unwrap();
        // println!("Allocated inode in group {}, bitmap looks like {}", group_i, bm[usize::try_from(inode_number / 8).unwrap()]);
        if inode_number == 0 {
            return Err("Error finding inode.")
        }
        // Recontextualize inode number from within group to global number
        let inode_number = u32::try_from(group_i).unwrap() * self.superblock.inodes_per_group + inode_number;
        Ok(inode_number.try_into().unwrap())
    }

    // free up an inode that is no longer in use
    pub fn free_inode(&mut self, inode: usize) -> std::result::Result<(),&str> {
        // if inode is a directory, unlink everything
        // problem: if a directory is linked to by a descendant,
        // it will be unreachable but never cleaned up
        if self.get_inode(inode).type_perm & structs::TypePerm::DIRECTORY == structs::TypePerm::DIRECTORY {
            let mut directory = self.read_dir_inode(inode).unwrap().clone();
            let mut children: Vec<String> = vec![];
            for (i, name) in directory {
                if !name.to_string().eq(".") { children.push(name.to_string()); }
            }
            for name in children {
                self.unlink(inode, name);
            }
        }

        let which_group = (inode - 1) / usize::try_from(self.superblock.inodes_per_group).unwrap();
        let which_inode = (inode - 1) % usize::try_from(self.superblock.inodes_per_group).unwrap();
        let mut group = &mut self.block_groups[which_group];
        group.free_inodes_count += 1;
        let inode_bitmap_addr = group.inode_usage_addr;
        let which_byte = usize::try_from(which_inode / 8).unwrap();
        let which_bit = usize::try_from(which_inode % 8).unwrap();
        let mut inode_bitmap = self.read_dir_block(usize::try_from(inode_bitmap_addr).unwrap()).unwrap();
        inode_bitmap[which_byte] = inode_bitmap[which_byte] & (!(1 << which_bit));
        let mut inode = self.get_inode(inode);
        // todo: make this work with large inodes
        for block in inode.direct_pointer {
            if block == 0 {
                break
            }
            self.free_block(block.try_into().unwrap());
        }
        Ok(())
    }

    // find free block and allocate it for use
    pub fn allocate_block(&mut self) -> usize {
        let mut group = 0;
        for g in 0..self.block_groups.len() {
            if self.block_groups[g].free_blocks_count > 0 {
              group = g;
              break
            }
        }

        let mut block_bitmap: &mut [u8] = self.read_dir_block(usize::try_from(self.block_groups[group].block_usage_addr).unwrap()).unwrap();
        let mut block_number = 0;
        for i in 1..=self.superblock.inodes_per_group {
            //println!("Block bitmap: {}", block_bitmap[usize::try_from(i).unwrap()]);
            let which_byte = usize::try_from(i / 8).unwrap();
            let which_bit = usize::try_from(i % 8).unwrap();
            //println!("Block bitmap & which_bit: {}", block_bitmap[usize::try_from(i).unwrap()]);
            // If the bit is free (0 is free, 1 is in use)
            if block_bitmap[which_byte] & (1 << which_bit) == 0 {
                block_number = i;
                block_bitmap[which_byte] = block_bitmap[which_byte] | (1 << which_bit);
                break
            }
        }

        let final_block = group * (self.superblock.blocks_per_group as usize) + (block_number as usize);

        // println!("Allocated block {}", final_block);
        
        // clean out old data
        let mut block = self.read_dir_block(final_block).unwrap();
        for i in 0..self.block_size {
          block[i] = 0;
        }
        
        final_block
    }

    // free up block from deleted file
    pub fn free_block(&mut self, block: usize) -> std::result::Result<(),&str> {
        let which_group = block / usize::try_from(self.superblock.blocks_per_group).unwrap();
        let which_block = block % usize::try_from(self.superblock.blocks_per_group).unwrap();
        let mut group = &mut self.block_groups[which_group];
        group.free_blocks_count += 1;
        let block_bitmap_addr = group.block_usage_addr;
        let which_byte = usize::try_from(which_block / 8).unwrap();
        let which_bit = usize::try_from(which_block % 8).unwrap();
        let mut block_bitmap = self.read_dir_block(usize::try_from(block_bitmap_addr).unwrap()).unwrap();
        block_bitmap[which_byte] = block_bitmap[which_byte] & (!(1 << which_bit));
        Ok(())
    }

    // number of children a directory has that have a link to it
    // used to determine if a directory is reachable
    pub fn num_directory_children(&self, inode: usize) -> usize {
        if self.get_inode(inode).type_perm & structs::TypePerm::DIRECTORY != structs::TypePerm::DIRECTORY {
            return 0;
        }

        let directory = self.read_dir_inode(inode).unwrap();
        let mut children: Vec<usize> = vec![];
        for (i, name) in directory {
            // don't include parent
            if !name.to_string().eq("..") { children.push(i); }
        }
        let mut num = 0;
        for i in children {
            let data = self.get_inode(i);
            if data.type_perm & structs::TypePerm::DIRECTORY == structs::TypePerm::DIRECTORY {
                num += 1;
            }
        }
        num
    }

    // create a hardlink from a directory to an inode
    pub fn link(&self, dir_inode: usize, link_inode: usize, name: String) -> Result<()> {
        let directory = self.get_inode(dir_inode);
        //println!("Linking, my direct pointer is {}", directory.direct_pointer[0]);
        let entry_ptr = self.blocks[directory.direct_pointer[0] as usize - self.block_offset].as_ptr();
        let mut byte_offset: isize = 0;
        while byte_offset < directory.size_low as isize { // <- todo, support large directories
            let new_directory = unsafe {
                &mut *(entry_ptr.offset(byte_offset) as *mut DirectoryEntry) 
            };
            //println!("{:?}", new_directory);
            
            if new_directory.entry_size == 0 {
              break;
            }

            // the final directory entry has a size that takes up the rest of the directory
            if new_directory.entry_size as isize + byte_offset >= directory.size_low as isize {
                let real_size = u16::try_from(4 + 2 + 1 + mem::size_of::<TypeIndicator>() + new_directory.name.as_bytes().len() + 1).unwrap();
                // inode ptr size + entry size size + name size size + type indicator size + name size + null character
                new_directory.entry_size = real_size;
                byte_offset += real_size as isize;
                break;
            }
            byte_offset += new_directory.entry_size as isize;
        }
        let new_directory = unsafe {
            &mut *(entry_ptr.offset(byte_offset) as *mut DirectoryEntry)
        };
        //println!("{:?}",new_directory);
        new_directory.inode = u32::try_from(link_inode).unwrap();
        println!("Linking from inode {} to inode {}", dir_inode, new_directory.inode);
        new_directory.name_length = u8::try_from(name.len()).unwrap();
        new_directory.type_indicator = TypeIndicator::Directory;
        let mut name_iter = new_directory.name.as_bytes_mut().as_mut_ptr();
        let mut name_offset = 0;
        // perform pointer arithmetic to set each byte of the name to the correct character
        for c in name.as_bytes() {
            unsafe { *name_iter.offset(name_offset) = *c; } 
            name_offset += 1;
        }
        // add null termination
        unsafe { *name_iter.offset(name_offset) = 0; }
        // this is the new final directory entry, so its size must fill the rest of the directory 
        new_directory.entry_size = u16::try_from(directory.size_low).unwrap() - u16::try_from(byte_offset).unwrap();
        
        let linked = self.get_inode(link_inode);
        linked.hard_links += 1;
        Ok(())
    }

    //remove a hardlink from a directory with name "name" and free inodes if relevant
    pub fn unlink(&mut self, dir_inode: usize, name: String) -> std::result::Result<(), &str> {
        let directory = self.read_dir_inode(dir_inode).unwrap();
        let mut target_inode = 0;
        let mut found_target = false;
        for (i_num, i_name) in directory {
            if i_name.to_string().eq(&name) {
                target_inode = i_num;
                found_target = true;
                break;
            }
        }
        if !found_target {
            return Err("No item with that name was found.");
        }

        //println!("Unlinking inode {}", target_inode);

        let mut removed_size = 0;
        let mut pivot_byte = 0;
        let directory_inode = self.get_inode(dir_inode);
        let entry_ptr = self.blocks[directory_inode.direct_pointer[0] as usize - self.block_offset].as_ptr();
        let mut byte_offset: isize = 0;
        while byte_offset < directory_inode.size_low as isize { // <- todo, support large directories
            if removed_size == 0 {
                let new_directory = unsafe {
                    &mut *(entry_ptr.offset(byte_offset) as *mut DirectoryEntry) 
                };
            
                if new_directory.entry_size == 0 {
                  break;
                }

                if new_directory.inode == target_inode.try_into().unwrap() { // find inode to unlink
                    removed_size = new_directory.entry_size;
                    pivot_byte = byte_offset;
                } else {
                    byte_offset += isize::try_from(new_directory.entry_size).unwrap();
                }
            } else { // for every byte after the unlinked inode, shift left a number of bytes equal to the size of the removed inode
                let byte = unsafe {
                  &mut *(entry_ptr.offset(byte_offset) as *mut u8)
                };

                let change_to = unsafe {
                  // pad the right edge with 0s
                  if byte_offset + isize::try_from(removed_size).unwrap() >= self.block_size.try_into().unwrap() { 0 } else { *(entry_ptr.offset(byte_offset + isize::try_from(removed_size).unwrap()) as *const u8) }
                };

                *byte = change_to;

                byte_offset += 1;
            }
        }

        let mut byte_offset: isize = 0;
        let mut last_entry = unsafe { &mut *(entry_ptr as *mut DirectoryEntry) };
        let mut size = last_entry.entry_size;
        // find final element of directory
        while size != 0 {
            let new_directory = unsafe {
                &mut *(entry_ptr.offset(byte_offset) as *mut DirectoryEntry) 
            };
            size = new_directory.entry_size;
            byte_offset += isize::try_from(size).unwrap();
            if new_directory.entry_size == 0 {
              break
            }
            last_entry = new_directory;
        }
        // we need to add the size back in to the final element so the directory is "full"
        last_entry.entry_size += removed_size;
        
        let target = self.get_inode(target_inode.try_into().unwrap());
        if target.hard_links > 0 { target.hard_links -= 1; }
        if usize::from(target.hard_links) <= self.num_directory_children(target_inode) && target_inode != 2 {
            // free up inode if it's now unreachable (unless it's the root inode)
            self.free_inode(target_inode.try_into().unwrap());
        }
        Ok(())
    }
}

impl fmt::Debug for Inode<> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.size_low == 0 && self.size_high == 0 {
            f.debug_struct("").finish()
        } else {
            f.debug_struct("Inode")
            .field("type_perm", &self.type_perm)
            .field("size_low", &self.size_low)
            .field("direct_pointers", &self.direct_pointer)
            .field("indirect_pointer", &self.indirect_pointer)
            .finish()
        }
    }
}

// turn a path string into a vector of steps along the path
fn parse_path(from: &str) -> Vec<&str> {
    from.split('/')
        .collect()
}

// get the inode number of an inode given the relative path to it
fn relative_path<'a>(path: &'a str, from: Vec<(usize, &'a NulStr)>, fs: &'a Ext2) -> std::result::Result<usize, &'a str> {
    let mut target: Vec<(usize, &NulStr)> = (from).to_vec();
    let mut target_inode: usize = 2;
    let mut temp: Vec<(usize, &NulStr)> = target.clone();
    for child in parse_path(path).iter() {
        let mut found = false;
        for (addr, name) in target.iter() {
            if name.to_string().eq(child) {
                temp = match fs.read_dir_inode(*addr) { // if we find a matching child, set target to that and iterate
                    Ok(dir_listing) => dir_listing,
                    Err(_) => { println!("unable to read cwd"); break; } // dir has child, but child cannot be read
                };
                target_inode = *addr;
                found = true;
                break;
            }
        }
        if !found {
            return Err("No file or directory found with that path.");
        } else {
            target = temp.clone();
        }
    }
    Ok(target_inode)
}

// flush entire file system out
fn flush(fs: &Ext2, name: String) {
    fs::write(name, fs.start_ptr).unwrap();
}

fn main() -> Result<()> {
    let fname = args().nth(1).expect("No file given");
    let disk = &mut fs::read(fname.clone()).expect("No such file exists");
    let start_addr: usize = disk.as_ptr() as usize;
    let mut disk_slice: &mut [u8] = &mut disk[..];
    let mut ext2 = Ext2::new(&mut disk_slice, start_addr);

    let mut current_working_inode:usize = 2;

    let mut rl = DefaultEditor::new()?;
    loop {
        // fetch the children of the current working directory
        let dirs = match ext2.read_dir_inode(current_working_inode) {
            Ok(dir_listing) => {
                dir_listing
            },
            Err(_) => {
                println!("unable to read cwd");
                break;
            }
        };

        let buffer = rl.readline(":> ");
        if let Ok(line) = buffer {
            if line.starts_with("ls") {
                // `ls` prints our cwd's children
                // TODO: support arguments to ls (print that directory's children instead)
                let mut target = dirs;
                let args = line.split(' ').collect::<Vec<&str>>();
                if args.len() > 1 {
                    target = match relative_path(args[1],target.clone(),&ext2) {
                        Ok(t) => match ext2.read_dir_inode(t) { Ok(d) => d, Err(_) => target },
                        Err(_) => target,
                    };
                }
                for dir in &target {
                    print!("{}\t", dir.1);
                }
                println!();
            } else if line.starts_with("cd") {
                // `cd` with no arguments, cd goes back to root
                // `cd dir_name` moves cwd to that directory
                let elts: Vec<&str> = line.split(' ').collect();
                if elts.len() == 1 {
                    current_working_inode = 2;
                } else {
                    let mut found_self = false;
                    let target = match relative_path(elts[1],dirs.clone(),&ext2) {
                        Ok(t) => { found_self = true; t },
                        Err(_) => { println!("unable to locate {}, cwd unchanged", elts[1]); current_working_inode },
                    };
                    if found_self { 
                        let inode: &Inode = ext2.get_inode(target);
                        // check if directory flag is set (& DIRECTORY masks out other flags, == DIRECTORY compares flag)
                        if inode.type_perm & structs::TypePerm::DIRECTORY == structs::TypePerm::DIRECTORY{
                            current_working_inode = target;
                            println!("cwd is now {}", target);
                        } else {
                            println!("Destination is not a directory, cwd unchanged.");
                        }
                    }
                }
            } else if line.starts_with("mkdir") {
                // `mkdir childname`
                // create a directory with the given name, add a link to cwd
                // consider supporting `-p path/to_file` to create a path of directories
                let args = line.split(' ').collect::<Vec<&str>>();
                if args.len() <= 1 {
                    println!("No name given, mkdir failed");
                    continue
                }
                
                let (path, name) = match args[1].rsplit_once("/") {
                  Some(o) => o,
                  None => ("", args[1]),
                };

                if ext2.superblock.free_inodes_count == 0 {
                    println!("File system full, mkdir failed");
                    continue
                }
                
                let mut found_self = false;
                let dirs = match path {
                  "" => {found_self = true; dirs},
                  _ => match relative_path(path, dirs.clone(), &ext2) {
                      Ok(t) => {found_self = true; ext2.read_dir_inode(t).unwrap()}
                      Err(_) => {println!("Unable to locate {}, mkdir failed", path); dirs }
                  },
                };

                let mut cwd = 0;
                for dir in dirs {
                  if dir.1.to_string().eq(".") {
                    cwd = dir.0; // a directory should have a link to itself under "."
                    break
                  }
                }
                if cwd == 0 {
                  println!("Couldn't navigate, mkdir failed");
                  continue
                }

                if !found_self {
                  println!("Error while navigating, mkdir failed");
                  continue
                }

                let allocated_block = ext2.allocate_block();
                let inode_number = ext2.allocate_inode().unwrap();
                let inode: &mut Inode = ext2.get_inode(inode_number.try_into().unwrap());
                inode.type_perm = structs::TypePerm::DIRECTORY | structs::TypePerm::U_READ;
                inode.size_low = 1024 << ext2.superblock.log_block_size;
                inode.hard_links = 0;
                inode.direct_pointer[0] = allocated_block as u32;
                // link self to cwd, link self to self, link cwd to self
                ext2.link(cwd, inode_number.try_into().unwrap(), name.to_string());
                ext2.link(inode_number.try_into().unwrap(), inode_number.try_into().unwrap(), ".".to_string());
                ext2.link(inode_number.try_into().unwrap(), cwd.try_into().unwrap(), "..".to_string());
            } else if line.starts_with("cat") {
                // `cat filename`
                // print the contents of filename to stdout
                // if it's a directory, print a nice error
                let elts: Vec<&str> = line.split(' ').collect();
                if elts.len() == 1 {
                    println!("Command `cat` expected one argument, no arguments given.");
                } else {
                    let mut found_file = false;
                    let target = match relative_path(elts[1],dirs.clone(),&ext2) {
                        Ok(t) => { found_file = true; t },
                        Err(_) => { println!("unable to locate {}, cwd unchanged", elts[1]); current_working_inode },
                    };
                    if found_file { 
                        let inode: &Inode = ext2.get_inode(target);
                        // check if file flag is set (& FILE masks out other flags, == FILE compares flag)
                        if inode.type_perm & structs::TypePerm::FILE == structs::TypePerm::FILE {
                            let mut current_size: usize = 0;
                            for direct in inode.direct_pointer { // TODO: Add support for large files
                                if current_size >= inode.size_low.try_into().unwrap() {
                                    break
                                }
                                let block = ext2.read_dir_block(direct as usize);
                                match block {
                                    Ok(b) => {
                                        for c in b {
                                            print!("{}", *c as char);
                                        }
                                    },
                                    Err(e) => println!("{}",e),
                                }
                                current_size += 1 << (ext2.superblock.log_block_size + 10);
                            }
                        } else {
                            println!("Destination is not a file.");
                        }
                    }
                }
            } else if line.starts_with("rm") {
                // `rm target`
                // unlink a file or empty directory
                let args = line.split(' ').collect::<Vec<&str>>();

                if args.len() <= 1 {
                  println!("Command `rm` expected one argument, no arguments given.");
                  continue
                }
                
                if args[1].eq(".") || args[1].eq("..") {
                    println!("Cannot delete a directory while inside of it.");
                }

                let (path, name) = match args[1].rsplit_once("/") {
                  Some(o) => o,
                  None => ("", args[1]),
                };

                let mut found_self = false;
                let directory = match path { 
                    "" => {found_self = true; let mut t = 0; for (num, name) in dirs { if name.to_string().eq(".") { t = num; break } }; t},
                    p => match relative_path(p, dirs.clone(), &ext2) {
                        Ok(t) => {found_self = true; t},
                        Err(_) => {println!("Unable to locate {}, rm failed", args[1]); 0},
                    },
                };

                if found_self == false {
                    continue
                }

                ext2.unlink(directory, name.to_string());
            } else if line.starts_with("flush") {
                flush(&ext2, fname.clone());
            } else if line.starts_with("mount") {
                // `mount host_filename mountpoint`
                // mount an ext2 filesystem over an existing empty directory
                println!("mount not yet implemented");
            } else if line.starts_with("link") {
                // `link arg_1 arg_2`
                // create a hard link from arg_1 to arg_2
                // consider what to do if arg2 does- or does-not end in "/"
                // and/or if arg2 is an existing directory name
                let args = line.split(' ').collect::<Vec<&str>>();
                if args.len() == 1 {
                  println!("Command `link` expected two arguments, no arguments given.");
                  continue
                } else if args.len() == 2 {
                  println!("Command `link` expected two arguments, one argument given.");
                  continue
                }
                
                let source = args[1];
                let mut found_self = false;
                let source_inode = match relative_path(source, dirs.clone(), &ext2) {
                    Ok(t) => {found_self = true; t},
                    Err(_) => {println!("Unable to locate {}, mkdir failed", source); 0 },
                };
        
                if found_self == false {
                    continue
                }
  
                let (dest_path, dest_name) = match args[2].rsplit_once("/") {
                  Some(o) => o,
                  None => ("", args[2]),
                };
                let mut found_self = false;
                // if a path is given, follow the path. otherwise, use cwd
                let dest_dir_inode = match dest_path {
                  "" => {found_self = true; let mut t = 0; for (num, name) in dirs { if name.to_string().eq(".") { t = num; break } }; t },
                  _ => match relative_path(dest_path, dirs.clone(), &ext2) {
                      Ok(t) => {found_self = true; t},
                      Err(_) => {println!("Unable to locate {}, mkdir failed", dest_path); 0 },
                  },
                };

                if found_self == false {
                  continue
                }

                ext2.link(dest_dir_inode, source_inode, dest_name.to_string());
            } else if line.starts_with("quit") || line.starts_with("exit") {
                break;
            }
        } else {
            println!("bye!");
            break;
        }
    }
    Ok(())
}
