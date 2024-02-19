use std::borrow::Borrow;
use std::fs::OpenOptions;
use std::io::SeekFrom;
use std::ops::Range;
use std::{error::Error, fs::File, io::Seek};


use super::page::{ NULL_IDX, DEFAULT_ROOT_IDX, DEFAULT_PAGE0_IDX, METADATA_IDX };

use super::page::{ PagePointer, PAGE_SIZE, Page };
use super::page::{ LeafPage, DirectoryPage, MetadataPage, FreePage };

pub type BPlusResult<T> = Result<T, Box<dyn Error>>;


#[derive(Debug)]
pub struct BPlusTree
{
  file: File,
  meta: MetadataPage
}

#[derive(Debug)]
pub struct BPlusTreeIterator<'a>
{
  tree: &'a mut BPlusTree,
  page: LeafPage,
  idx: usize
}

fn seek_addr(idx: PagePointer) -> SeekFrom
{
  SeekFrom::Start(idx * (PAGE_SIZE as u64))
}

#[allow(dead_code)]
impl BPlusTree
{

  /// Initialize a brand new BPlusTree at the provided path
  pub fn init(path: &String) -> BPlusResult<BPlusTree>
  {
    let mut file = 
      OpenOptions::new()
                 .create(true)   // Create file if not present
                 .truncate(true) // Empty the file if it is
                 .read(true)     // Allow reads
                 .write(true)    // Allow writes
                 .open(path)?;

    // Write initial metadata page
    let meta = MetadataPage::init(
      /* next_free_page */  NULL_IDX,
      /* root_page */       DEFAULT_ROOT_IDX,
      /* data_head */       DEFAULT_PAGE0_IDX,
      /* data_tail */       DEFAULT_PAGE0_IDX,
      /* pages_allocated */ 3,
      /* depth */           1,
    );
    file.seek(seek_addr(METADATA_IDX))?;
    meta.write(&mut file)?;

    // Write initial root directory page
    let mut root = DirectoryPage::init();
    root.pointers[0] = DEFAULT_PAGE0_IDX;
    file.seek(seek_addr(DEFAULT_ROOT_IDX))?;
    root.write(&mut file)?;

    // Write initial data page
    let data = LeafPage::init();
    file.seek(seek_addr(DEFAULT_PAGE0_IDX))?;
    data.write(&mut file)?;

    Ok(BPlusTree { file, meta })
  }

  /// Open an existing BPlusTree at the provided path
  pub fn open(path: &String) -> BPlusResult<BPlusTree>
  {
    let mut file = 
      OpenOptions::new()
                 .read(true)     // Allow reads
                 .write(true)    // Allow writes
                 .open(path)?;

    file.seek(seek_addr(METADATA_IDX))?;
    let meta = MetadataPage::read(&mut file)?;

    Ok(BPlusTree { file, meta })
  }

  ////////////////////////////////////////////////////////////////
  //////////////////// Part 1: Page Management ///////////////////
  ////////////////////////////////////////////////////////////////

  /// Write the content of the provided page to a free page
  ///  - Available pages freed with free_page should be used first
  ///  - If no existing free page exists, allocate a new page by
  ///    writing to the end of the file
  /// 
  /// This function should ensure that the file metadata page is 
  /// up-to-date after the page is written.
  /// 
  /// This function should:
  /// - Use O(1) memory
  /// - Perform O(1) IOs
  /// - Have an O(1) runtime 
  pub fn alloc_page<T: Page>(&mut self, page: &T) -> BPlusResult<PagePointer>
  {
    todo!();
  }

  /// Release the page for use in a new context.  The freed pointer
  /// may be freely overwritten.
  /// 
  /// This function should ensure that the file metadata page is 
  /// up-to-date after the page is written.
  /// 
  /// This function should:
  /// - Use O(1) memory
  /// - Perform O(1) IOs
  /// - Have an O(1) runtime 
  pub fn free_page(&mut self, ptr: PagePointer) -> BPlusResult<()>
  {
    todo!();
  }

  /// Retrieve the content of a disk page and decode it.
  ///
  /// For example, the following code retrieves the DirectoryPage
  /// located on page 3:
  /// ```
  /// let page = tree.get_page::<DirectoryPage>(3)?
  /// ```
  ///
  /// This function should:
  /// - Use O(1) memory
  /// - Perform O(1) IOs
  /// - Have an O(1) runtime 
  pub fn get_page<T: Page>(&mut self, ptr: PagePointer) -> BPlusResult<T>
  {
    self.file.seek(seek_addr(ptr))?;
    let ret = T::read(&mut self.file)?;
    assert!(ret.page_type() == T::EXPECTED_PAGE_TYPE);
    Ok(ret)
  }

  /// Write the content of an in-memory page to disk
  ///
  /// This function should:
  /// - Use O(1) memory
  /// - Perform O(1) IOs
  /// - Have an O(1) runtime 
  pub fn put_page<T: Page>(&mut self, ptr: PagePointer, page: &T) -> BPlusResult<()>
  {
    // SNIP ALT:todo!()
    self.file.seek(seek_addr(ptr))?;
    page.write(&mut self.file)
  }

  /// Write the metadata page to disk
  ///
  /// Shorthand for self.put_page(METADATA_IDX, self.meta)
  pub fn put_meta(&mut self) -> BPlusResult<()>
  {
    self.put_page(METADATA_IDX, &self.meta.clone())
  }

  ////////////////////////////////////////////////////////////////
  ////////////////////// Read Methods ////////////////////////////
  ////////////////////////////////////////////////////////////////

  /// Retrieve a specific key, if present
  pub fn get(&mut self, key: u32) -> BPlusResult<Option<u32>>
  {
    let v = self.find_page(key)?;
    let ptr = v[v.len()-1];
    let page = self.get_page::<LeafPage>(ptr)?;
    Ok(page.find_value(key))
  }

  /// Iterate over all of the data values
  pub fn iter<'a>(&'a mut self) -> BPlusResult<BPlusTreeIterator<'a>>
  {
    let data_idx = self.meta.data_head.to_owned();
    let data_page = self.get_page::<LeafPage>(data_idx)?;

    Ok(BPlusTreeIterator { 
      tree: self, 
      page: data_page, 
      idx: 0
    })
  }

  ////////////////////////////////////////////////////////////////
  /////////////////// Part 2: Insertion //////////////////////////
  ////////////////////////////////////////////////////////////////


  /// Insert a new key/value pair into the dataset.
  ///
  /// With N records and K keys per directory page, this 
  /// function's asymptotic bounds should be:
  /// - Memory: O(log_K(N))
  /// - IO: O(log_K(N)) reads, O(1) amortized writes.
  ///
  /// Amortized bounds may assume no intervening calls
  /// to delete()
  ///
  /// You are encouraged to write this function in several steps:
  /// 1. First solve the case where the leaf that would hold 
  ///    key has sufficient space; Leave a todo!() for the 
  ///    other case
  /// 2. Then solve the case where the leaf that would hold
  ///    key needs to be split; Leave a todo!() for the case
  ///    where the parent directory page needs to be split.
  /// 3. Then solve the case where the parent directory page
  ///    is the root and needs to be split.  Leave a todo!() for
  ///    the case where a non-root directory page needs to be
  ///    split.
  /// 4. Finally solve the case where the a non-root directory 
  ///    page needs to be split.
  /// 
  /// You are also encouraged to use several helper functions:
  /// - LeafPage::split()
  /// - DirectoryPage::split_ptr()
  /// - DirectoryPage::split()
  /// - BPlusTree::find_page()
  ///
  pub fn put(&mut self, key: u32, value: u32) -> BPlusResult<()>
  {
    todo!();
  }

  ////////////////////////////////////////////////////////////////
  //////////////////// Part 2: Deletion //////////////////////////
  ////////////////////////////////////////////////////////////////
  
  /// Delete a key from the tree
  ///
  /// With N records and K keys per directory page, this 
  /// function's asymptotic bounds should be:
  /// - Memory: O(log_K(N))
  /// - IO: O(log_K(N)) reads, O(1) amortized writes.
  ///
  /// Amortized bounds may assume no intervening calls
  /// to put()
  ///
  /// You are encouraged to write this function in several steps:
  /// 1. First solve the case where the leaf that holds the key
  ///    is at least 50% full after the deletion, and does not 
  ///    require a merge.  Leave a todo!() for the other cases.
  /// 2. Next, solve the case where one of the leaves adjacent
  ///    to the underfull leaf has keys that can be stolen.  
  ///    Leave a todo!() for the other cases.
  /// 3. Then, solve the case where the parent of the leaf
  ///    is at least 50% full after losing a pointer, and so
  ///    does not require a recursive merge.  Leave a todo!() 
  ///    for the other cases.
  /// 4. After that, solve the case where an adjacent sibling of
  ///    the parent of the leaf has keys that can be stolen.
  ///    Leave a todo!() for the other cases.
  /// 5. Fifth, solve the case where the parent of the leaf is
  ///    a root page that contains >= 2 pointers after losing
  ///    a pointer.  Leave a todo!() for the other cases. (Hint:
  ///    this case is really really easy :) )
  /// 6. Next, solve the case where the parent of the leaf is
  ///    not a root page.  Leave a todo!() for the final case.
  /// 7. Finally, solve the case where the deletion drops the
  ///    root page down to a single pointer (with no keys).
  /// 
  /// You are also encouraged to use several helper functions:
  /// - BPlusTree::find_page()
  /// - LeafPage::is_underfull()
  /// - LeafPage::can_allow_stolen_key()
  /// - LeafPage::steal_low()
  /// - LeafPage::steal_high()
  /// - DirectoryPage::is_underfull()
  /// - DirectoryPage::can_allow_stolen_key()
  /// - DirectoryPage::steal_low()
  /// - DirectoryPage::steal_high()
  ///
  pub fn delete(&mut self, key: u32) -> BPlusResult<()>
  {
    todo!()
  }

  ////////////////////////////////////////////////////////////////
  /////////////////// Utility Functions //////////////////////////
  ////////////////////////////////////////////////////////////////

  /// Recover the page path from the root to the leaf containing the 
  /// specified key
  /// 
  /// - The first page pointer returned is the root
  /// - The final page pointer in the is the leaf containing (or 
  ///   that would contain the key)
  pub fn find_page(&mut self, key: u32) -> BPlusResult<Box<[PagePointer]>>
  {
    let mut ret: Vec<PagePointer> = Vec::new();
    let mut curr_ptr = self.meta.root_page;
    ret.push(curr_ptr);

    for _i in (Range { start: 0, end: self.meta.depth })
    {
      let dir = self.get_page::<DirectoryPage>(curr_ptr)?;
      curr_ptr = dir.find_pointer(key);
      ret.push(curr_ptr);
    }

    return Ok(ret.into_boxed_slice())
  }

  /// Return the depth of the tree
  pub fn depth(&self) -> u16
  {
    self.meta.depth
  }

  /// Sanity check the tree
  ///
  /// Returns a string containing the first problem it encounters
  /// or None if no errors are encountered.
  ///
  /// As usual, an error is reported if there's a problem.
  pub fn check_tree(&mut self) -> BPlusResult<Option<String>>
  {
    let mut dir_stack: Vec<(PagePointer, usize, u32, u32)> = Vec::new();

    let mut curr_ptr: PagePointer = self.meta.root_page;
    let mut curr_idx = 0;
    let mut low: u32 = 0;
    let mut high: u32 = u32::MAX;

    let mut last_data: PagePointer = 0;
    let mut next_data: PagePointer = self.meta.data_head;

    loop {
      // Descend to the next data page
      for _i in dir_stack.len() as u16 .. self.meta.depth
      {
        dir_stack.push( (
          curr_ptr,
          curr_idx,
          low,
          high
        ) );
        if curr_ptr >= self.meta.pages_allocated 
        { 
          if dir_stack.is_empty() { return Ok(Some(format!("Invalid root pointer for tree: {}", curr_ptr))); }
          else                    { return Ok(Some(format!("Invalid pointer: {} stored in directory page {}", curr_ptr, dir_stack.last().unwrap().0))); }
        }
        // println!("Descend into directory page {} at index {} (low = {}, high = {})", curr_ptr, curr_idx, low, high);
        let curr_dir_page: DirectoryPage = self.get_page(curr_ptr)?;
        if dir_stack.len() > 1 {
          if curr_dir_page.is_underfull() 
            { return Ok(Some(format!("Underfull page {}: {:?}", curr_ptr, curr_dir_page))); }
        } else {
          if curr_dir_page.count == 0 && self.meta.depth > 1
            { return Ok(Some(format!("Empty root page {}: {:?}", curr_ptr, curr_dir_page))); }
        }
        for k in curr_dir_page.keys.iter().take(curr_dir_page.count)
        {
          if *k < low   { return Ok(Some(format!("Split Key {} < Parent constraint {} on page {}: {:?}", k, low, curr_ptr, curr_dir_page))); }
          if *k >= high { return Ok(Some(format!("Split Key {} >= Parent constraint {} on page {}: {:?}", k, high, curr_ptr, curr_dir_page))); }
        }
        curr_ptr = curr_dir_page.pointers[curr_idx];
        if curr_idx > 0                        { low = curr_dir_page.keys[curr_idx-1]; }
        if curr_dir_page.count > 0
           && curr_idx < curr_dir_page.count-1 { high = curr_dir_page.keys[curr_idx]; }
        curr_idx = 0;
      }

      // println!("Visit leaf page {} (prev = {}, curr = {}; low = {}, high = {})", last_data, next_data, curr_ptr, low, high);
      // Sanity check the current leaf page
      if curr_ptr >= self.meta.pages_allocated 
      { 
        if dir_stack.is_empty() { return Ok(Some(format!("Invalid root pointer for tree: {}", curr_ptr))); }
        else                    { return Ok(Some(format!("Invalid pointer: {} stored in directory page {}", curr_ptr, dir_stack.last().unwrap().0))); }
      }
      let curr_leaf_page: LeafPage = self.get_page(curr_ptr)?;
      if curr_leaf_page.is_underfull() && self.meta.depth > 1 
        { return Ok(Some(format!("Underfull page {}: {:?}", curr_ptr, curr_leaf_page))); }
      for (k, _) in curr_leaf_page.iter()
      {
        if *k < low   { return Ok(Some(format!("Split Key {} < Parent constraint {} on page {}: {:?}", k, low, curr_ptr, curr_leaf_page))); }
        if *k >= high { return Ok(Some(format!("Split Key {} >= Parent constraint {} on page {}: {:?}", k, high, curr_ptr, curr_leaf_page))); }
      }
      if next_data != curr_ptr            { return Ok(Some(format!("Next pointer != {} on page {}", next_data, curr_ptr))); }
      if last_data != curr_leaf_page.prev { return Ok(Some(format!("Prev pointer != {} on page {}: {:?}", last_data, curr_ptr, curr_leaf_page))); }
      next_data = curr_leaf_page.next;
      last_data = curr_ptr;

      // Ascend until we have a 'next'
      (curr_ptr, curr_idx, low, high) = dir_stack.pop().unwrap();
      if curr_ptr >= self.meta.pages_allocated 
      { 
        if dir_stack.is_empty() { return Ok(Some(format!("Invalid root pointer for tree: {}", curr_ptr))); }
        else                    { return Ok(Some(format!("Invalid pointer: {} stored in directory page {}", curr_ptr, dir_stack.last().unwrap().0))); }
      }
      let mut curr_dir_page: DirectoryPage = self.get_page(curr_ptr)?;
      // println!("Ascend to directory page {} from index {} / {}", curr_ptr, curr_idx, curr_dir_page.count);
      while curr_idx >= curr_dir_page.count
      {
        (curr_ptr, curr_idx, low, high) = 
          match dir_stack.pop() {
            Some(s) => s,
            None => {
              if next_data != 0                   { return Ok(Some(format!("Last data page {} points to {} and not NULL", last_data, next_data)))}
              if last_data != self.meta.data_tail { return Ok(Some(format!("Metadata tail pointer points to {} and not {}", self.meta.data_tail, last_data)))}
              return Ok(None)
            }
          };
        if curr_ptr >= self.meta.pages_allocated 
        { 
          if dir_stack.is_empty() { return Ok(Some(format!("Invalid root pointer for tree: {}", curr_ptr))); }
          else                    { return Ok(Some(format!("Invalid pointer: {} stored in directory page {}", curr_ptr, dir_stack.last().unwrap().0))); }
        }
        curr_dir_page = self.get_page(curr_ptr)?;
        // println!("Ascend to directory page {} from index {} / {}", curr_ptr, curr_idx, curr_dir_page.count);
      }
      curr_idx += 1;
    }
  }


  /// Helper function: print the entire tree
  pub fn print_tree(&mut self) -> BPlusResult<()>
  {
    fn rcr(tree: &mut BPlusTree, page: PagePointer, depth: u16)
      -> BPlusResult<()>
    {
      if depth < tree.meta.depth
      {
        let data = tree.get_page::<DirectoryPage>(page)?;
        println!("{}PAGE[{}] = {:?}\n", std::iter::repeat(" ").take((depth*2) as usize).collect::<String>(), page, data);
        for page in &data.pointers[0 .. data.count+1]
        {
          rcr(tree, page.clone(), depth+1)?;
        }
      } else
      {
        let data = tree.get_page::<LeafPage>(page)?;
        println!("{}PAGE[{}] = {:?}\n", std::iter::repeat(" ").take((depth*2) as usize).collect::<String>(), page, data);
      }
      Ok(())
    }
    rcr(self, self.meta.root_page, 0)
  }
}

impl<'a> Iterator for BPlusTreeIterator<'a>
{
    type Item = (u32, u32);

    fn next(&mut self) -> Option<Self::Item> {
      while self.idx >= self.page.count
      {
        if self.page.next == NULL_IDX
        {
          return None
        }
        else {
          let next_page = self.page.next;
          self.page = 
            self.tree.get_page(next_page)
                     .expect(format!("Couldn't read next page {}", next_page).as_str());
          self.idx = 0
        }
      }
      let ret = self.page.get(self.idx);
      self.idx += 1;
      return Some(ret);
    }
}