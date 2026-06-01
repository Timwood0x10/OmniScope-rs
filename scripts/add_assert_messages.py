#!/usr/bin/env python3
"""
Script to add descriptive messages to Rust assertions without messages.
This helps eliminate clippy warnings about missing assertion messages.
"""

import re
import sys
from pathlib import Path
from typing import Tuple, Optional


def find_assertion_end(content: str, start: int) -> int:
    """
    Find the end of an assertion macro call, handling nested parentheses.
    """
    depth = 0
    i = start
    in_string = False
    escape_next = False
    
    while i < len(content):
        c = content[i]
        
        if escape_next:
            escape_next = False
            i += 1
            continue
        
        if c == '\\' and in_string:
            escape_next = True
            i += 1
            continue
        
        if c == '"' and not escape_next:
            in_string = not in_string
            i += 1
            continue
        
        if in_string:
            i += 1
            continue
        
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return i + 1
        
        i += 1
    
    return -1


def split_args(inner: str) -> list:
    """
    Split arguments by comma, respecting nested parentheses and strings.
    """
    parts = []
    depth = 0
    current = []
    in_string = False
    escape_next = False
    
    for c in inner:
        if escape_next:
            escape_next = False
            current.append(c)
            continue
        
        if c == '\\' and in_string:
            escape_next = True
            current.append(c)
            continue
        
        if c == '"' and not escape_next:
            in_string = not in_string
            current.append(c)
            continue
        
        if in_string:
            current.append(c)
            continue
        
        if c == '(':
            depth += 1
            current.append(c)
        elif c == ')':
            depth -= 1
            current.append(c)
        elif c == ',' and depth == 0:
            parts.append(''.join(current).strip())
            current = []
        else:
            current.append(c)
    
    if current:
        parts.append(''.join(current).strip())
    
    return parts


def process_assert(content: str, pos: int) -> Tuple[Optional[str], int]:
    """
    Process an assert! macro at the given position.
    Returns (new_content_or_None, new_position).
    """
    # Find the opening parenthesis
    paren_start = content.find('(', pos + len('assert!'))
    if paren_start == -1:
        return None, pos + len('assert!')
    
    # Find the matching closing parenthesis
    paren_end = find_assertion_end(content, paren_start)
    if paren_end == -1:
        return None, pos + len('assert!')
    
    # Get the content inside parentheses
    inner = content[paren_start + 1:paren_end - 1].strip()
    
    # Check if it already has a message
    parts = split_args(inner)
    if len(parts) >= 2:
        # Already has a message
        return None, paren_end
    
    # Generate message
    message = "Expected condition to be true"
    
    # Create new assertion with message
    new_assert = f'assert!({inner}, "{message}")'
    
    return new_assert, paren_end


def process_assert_eq(content: str, pos: int) -> Tuple[Optional[str], int]:
    """
    Process an assert_eq! macro at the given position.
    """
    macro_name = 'assert_eq!'
    macro_len = len(macro_name)
    
    # Find the opening parenthesis
    paren_start = content.find('(', pos + macro_len)
    if paren_start == -1:
        return None, pos + macro_len
    
    # Find the matching closing parenthesis
    paren_end = find_assertion_end(content, paren_start)
    if paren_end == -1:
        return None, pos + macro_len
    
    # Get the content inside parentheses
    inner = content[paren_start + 1:paren_end - 1].strip()
    
    # Split by commas
    parts = split_args(inner)
    
    # If already has 3 parts (left, right, message), skip
    if len(parts) >= 3:
        return None, paren_end
    
    # Generate message
    message = "Expected values to be equal"
    
    # Create new assertion with message
    new_assert = f'assert_eq!({inner}, "{message}")'
    
    return new_assert, paren_end


def process_assert_ne(content: str, pos: int) -> Tuple[Optional[str], int]:
    """
    Process an assert_ne! macro at the given position.
    """
    macro_name = 'assert_ne!'
    macro_len = len(macro_name)
    
    # Find the opening parenthesis
    paren_start = content.find('(', pos + macro_len)
    if paren_start == -1:
        return None, pos + macro_len
    
    # Find the matching closing parenthesis
    paren_end = find_assertion_end(content, paren_start)
    if paren_end == -1:
        return None, pos + macro_len
    
    # Get the content inside parentheses
    inner = content[paren_start + 1:paren_end - 1].strip()
    
    # Split by commas
    parts = split_args(inner)
    
    # If already has 3 parts (left, right, message), skip
    if len(parts) >= 3:
        return None, paren_end
    
    # Generate message
    message = "Expected values to be not equal"
    
    # Create new assertion with message
    new_assert = f'assert_ne!({inner}, "{message}")'
    
    return new_assert, paren_end


def process_file(filepath: str) -> bool:
    """
    Process a single Rust file, adding messages to assertions.
    Returns True if any changes were made.
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    result = []
    pos = 0
    changes = 0
    
    while pos < len(content):
        # Check for comments - skip if we're in a comment
        line_start = content.rfind('\n', 0, pos) + 1
        line = content[line_start:pos]
        if '//' in line:
            # We're in a comment line, skip to next line
            next_newline = content.find('\n', pos)
            if next_newline == -1:
                result.append(content[pos:])
                break
            result.append(content[pos:next_newline + 1])
            pos = next_newline + 1
            continue
        
        # Check for assert! (not assert_eq! or assert_ne!)
        if content[pos:].startswith('assert!') and not content[pos:].startswith('assert_eq!') and not content[pos:].startswith('assert_ne!'):
            new_content, new_pos = process_assert(content, pos)
            if new_content:
                result.append(new_content)
                changes += 1
            else:
                result.append(content[pos:new_pos])
            pos = new_pos
        
        # Check for assert_eq!
        elif content[pos:].startswith('assert_eq!'):
            new_content, new_pos = process_assert_eq(content, pos)
            if new_content:
                result.append(new_content)
                changes += 1
            else:
                result.append(content[pos:new_pos])
            pos = new_pos
        
        # Check for assert_ne!
        elif content[pos:].startswith('assert_ne!'):
            new_content, new_pos = process_assert_ne(content, pos)
            if new_content:
                result.append(new_content)
                changes += 1
            else:
                result.append(content[pos:new_pos])
            pos = new_pos
        
        else:
            result.append(content[pos])
            pos += 1
    
    new_content = ''.join(result)
    
    if changes > 0:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"  Modified {filepath}: {changes} assertions updated")
        return True
    
    return False


def main():
    """
    Main function to process all Rust files in the crates directory.
    """
    crates_dir = Path("crates")
    if not crates_dir.exists():
        print("Error: crates directory not found")
        sys.exit(1)
    
    # Find all Rust files
    rust_files = list(crates_dir.rglob("*.rs"))
    
    print(f"Found {len(rust_files)} Rust files to process")
    
    modified_files = 0
    total_files = len(rust_files)
    
    for filepath in rust_files:
        try:
            if process_file(str(filepath)):
                modified_files += 1
        except Exception as e:
            print(f"  Error processing {filepath}: {e}")
    
    print(f"\nSummary:")
    print(f"  Total files processed: {total_files}")
    print(f"  Files modified: {modified_files}")
    print(f"  Files unchanged: {total_files - modified_files}")


if __name__ == "__main__":
    main()
