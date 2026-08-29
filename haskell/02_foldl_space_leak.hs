-- THE BUG:         Summing with lazy `foldl`, which builds a chain of unevaluated
--                  thunks the size of the input instead of accumulating a number.
-- WHY IT'S MISSED: `foldl (+) 0 xs` is the obvious, correct-by-inspection way to
--                  add a list, and it gives the right answer on every small input.
--                  The defect is invisible because it is not a *wrong* answer --
--                  it is a *space* leak. Laziness means the accumulator is never
--                  forced during the fold, so `foldl` constructs
--                  `(((0 + 1) + 2) + 3) + ...` as a giant nested thunk and only
--                  collapses it at the very end. On a large list that thunk
--                  exhausts the stack (`*** Exception: stack overflow`) or balloons
--                  memory. The two-character difference between `foldl` and the
--                  strict `foldl'` decides whether the program runs in O(1) or
--                  O(n) space, and nothing in the source hints at it.
-- HOW TO DETECT:   Run with `+RTS -s` and watch maximum residency grow with input;
--                  heap profiling (`-hT`) shows the thunk pile-up. HLint suggests
--                  replacing `foldl` with `foldl'`.
-- THE FIX:         Use `Data.List.foldl'` (strict left fold) or `sum`, which force
--                  the accumulator each step and run in constant space.
--
-- Requires GHC (not installed in this build env). Run with:
--   runghc 02_foldl_space_leak.hs        -- the lazy fold; expect a stack overflow
--
-- EXPECTED BEHAVIOR (reasoned; not executed in this build env):
--   foldl  (+) 0 [1..10000000]  ->  *** Exception: stack overflow   (thunk chain)
--   foldl' (+) 0 [1..10000000]  ->  50000005000000                  (constant space)

import Data.List (foldl')

n :: Int
n = 10000000

lazySum :: Int
lazySum = foldl (+) 0 [1 .. n]      -- BUG: O(n) thunks, blows the stack

strictSum :: Int
strictSum = foldl' (+) 0 [1 .. n]   -- FIX: O(1) space, forces each step

main :: IO ()
main = do
    putStrLn $ "strict foldl' sum of [1.." ++ show n ++ "] = " ++ show strictSum
    putStrLn "now the lazy foldl (this is the buggy one):"
    print lazySum                   -- typically: *** Exception: stack overflow
    putStrLn ">>> If you reached this line, your stack was big enough to hide"
    putStrLn "    the leak today. On a larger list it crashes. Use foldl'."
