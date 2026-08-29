-- THE BUG:         A latent error -- a field set to `error "..."`, a div-by-zero,
--                  a partial pattern -- that lazy evaluation keeps dormant because
--                  the broken value is never forced. The program "works" until one
--                  day a new code path touches the field.
-- WHY IT'S MISSED: Non-strict evaluation means an expression is only computed if
--                  its result is actually demanded. So a record built with a
--                  genuinely broken field compiles, runs, passes its tests, and
--                  ships -- as long as nobody reads that field. The bug isn't on
--                  any line you execute; it's hiding inside a value you happened
--                  not to use. There is no stack trace, because nothing crashed.
--                  Then someone adds an innocent `print (timeoutMs cfg)` months
--                  later and a brand-new, "impossible" exception erupts from code
--                  that hasn't changed.
-- HOW TO DETECT:   `-Wall` will not flag it. Strictness annotations (`!field`, the
--                  `StrictData` / `BangPatterns` extensions) force fields at
--                  construction, turning dormant bugs into immediate, locatable
--                  ones. Forcing values in tests (`deepseq` / `evaluate`) exposes
--                  them.
-- THE FIX:         Make the data strict so the error fires where it's created:
--                  use strict fields (`data Config = Config !Int !String`) or the
--                  `StrictData` pragma, and never seed real data with `error`.
--
-- Requires GHC (not installed in this build env). Run with:  runghc 04_laziness_masks_bug.hs
--
-- EXPECTED OUTPUT (reasoned; not executed in this build env):
--   connecting to host: localhost
--   timeout (ms):
--   *** Exception: timeoutMs was never configured!
--   ...The first line prints fine; the bug stays dormant until the field is read.

data Config = Config
    { host      :: String
    , timeoutMs :: Int
    }

-- A config where one field is quietly broken. With lazy fields this is a
-- perfectly valid value as long as `timeoutMs` is never demanded.
defaultConfig :: Config
defaultConfig = Config
    { host      = "localhost"
    , timeoutMs = error "timeoutMs was never configured!"   -- dormant landmine
    }

main :: IO ()
main = do
    let cfg = defaultConfig
    putStrLn $ "connecting to host: " ++ host cfg     -- works: host is fine
    putStr   "timeout (ms): "
    print (timeoutMs cfg)                             -- BOOM: forces the landmine
    putStrLn ">>> The Config looked valid and the first line printed. The bug"
    putStrLn "    only detonates when the broken field is finally evaluated."

    -- THE FIX -- strict fields make the error fire at construction time:
    --   {-# LANGUAGE StrictData #-}
    --   data Config = Config { host :: String, timeoutMs :: !Int }
