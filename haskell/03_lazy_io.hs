-- THE BUG:         Lazy I/O. `readFile` does not read the file -- it returns a
--                  promise to read it later, as the string is consumed. Acting on
--                  the file before that promise is forced corrupts it.
-- WHY IT'S MISSED: The four lines read like a clean read-transform-write: get the
--                  contents, uppercase them, write them back. In a strict language
--                  this is correct. In Haskell, `readFile` is lazy: the handle is
--                  opened but the bytes are pulled on demand. The following
--                  `writeFile` to the *same path* runs while the read is still
--                  pending -- so GHC's single-writer lock fires
--                  ("resource busy (file locked)"), or, where no lock applies, the
--                  write truncates the file out from under the half-finished read
--                  and you get an empty or mangled result. The bug depends on
--                  evaluation order, not on the visible logic, so it survives
--                  every code review that "reads correctly".
-- HOW TO DETECT:   It often passes on tiny inputs (the lazy read finishes inside
--                  one buffer) and fails on real ones -- a classic "works on my
--                  machine". Forcing or switching to strict I/O makes it
--                  deterministic.
-- THE FIX:         Force the contents before writing
--                  (`length contents \`seq\` ...` or `evaluate`), or use strict
--                  I/O: `System.IO.readFile'` (base >= 4.15) or
--                  `Data.Text.IO.readFile`.
--
-- Requires GHC (not installed in this build env). Run with:  runghc 03_lazy_io.hs
--
-- EXPECTED BEHAVIOR (reasoned; not executed in this build env):
--   *** Exception: demo.txt: openFile: resource busy (file locked)
--   ...or, with no lock, demo.txt ends up empty/garbled instead of UPPERCASED.

import Data.Char (toUpper)
-- The fix would import: import System.IO (readFile')

main :: IO ()
main = do
    writeFile "demo.txt" "the quick brown fox\n"

    contents <- readFile "demo.txt"          -- LAZY: nothing read yet
    writeFile "demo.txt" (map toUpper contents)
        -- BUG: writing the file we are still lazily reading.

    result <- readFile "demo.txt"
    putStrLn $ "file now contains: " ++ show result
    putStrLn ">>> If this did not throw 'resource busy', the file was likely"
    putStrLn "    truncated mid-read. Force the read, or use readFile' (strict)."

    -- THE FIX:
    --   contents <- readFile' "demo.txt"     -- strict: fully read, handle closed
    --   writeFile "demo.txt" (map toUpper contents)
