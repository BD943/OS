# AI Usage Documentation
 
I built this project off the functionality of my original city manager program.
I used AI assistance while writing and checking the code, but the final project
was organized and tested by me.

Tool used:

- ChatGPT
- Claude 
Phase 1:
Prompts I used:

- I described my `Report` structure and asked for help writing a simple
  `parse_condition()` function for strings like `severity:>=:2`.
- I described the report fields and their C types, then asked for help writing
  a `match_condition()` function for severity, category, inspector, and
  timestamp.
- I asked for help checking the command functions for adding, listing, viewing,
  filtering, removing reports, updating the threshold, and showing metadata.

What AI helped generate:

- The basic idea for splitting a filter condition into `field`, `operator`,
  and `value`.
- The comparison logic for numbers and strings inside `match_condition()`.
- Suggestions for testing that the command functions were connected correctly
  in `main()`.

What I changed:
- I reviewed the generated filter logic and connected it myself to the loop
  that reads `reports.dat` one record at a time.
- I kept the permission checks, file creation, symbolic links, logging, and
  command handling in a simpler style that I can explain.

What I learned:

- How to split a command string into smaller parts in C.
- How to compare strings and numbers differently depending on the report field.
- How `stat()` permission bits can be checked manually for a simulated role.
- How `lseek()` and `ftruncate()` can remove one fixed-size binary record.

I also used AI to help check the project with `make`, `./build.sh`, and sample
commands for adding, listing, viewing, filtering, and removing reports.

Phase 2
 Where I Used AI

 -Throughout parts 1,2 and 3 of phase 2.
 

Why I Used AI

-For the rapid spotting of errors and fixing them every time something didn't compile or work as intended.
-Improve the code and remove unnecessary parts of it for efficiency and readability.
 
How I Used AI

-General debugging and testing 
- AI was used to draft command input scripts, which were subsequently reviewed, modified, and used to facilitate rapid and repeatable testing of functionality across the different parts of Phase 2.
- Where deemed appropriate, AI was used to make focused adjustments to existing functions for instance, simplifying logic or improving structure, while preserving the intended behaviour of the code.

 

 

 

 


