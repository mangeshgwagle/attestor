-- THE BUG:         Using `Int` (fixed 64-bit, silently wrapping) where the maths
--                  needs `Integer` (arbitrary precision). Haskell's reputation for
--                  correctness lulls you into trusting the number.
-- WHY IT'S MISSED: `Int` is the default integral type and the one every tutorial
--                  reaches for. The type signature `factorial :: Int -> Int` looks
--                  responsible, the function is a one-liner, and for every input
--                  you test by hand it is exactly right. Then a real input arrives,
--                  the product crosses 2^63, and `Int` wraps around in two's
--                  complement -- with NO exception, NO warning. `factorial 21`
--                  returns a *negative* number of orderings; `factorial 66`
--                  returns a clean, plausible-looking 0. A purely functional,
--                  total-looking function quietly produces nonsense.
-- HOW TO DETECT:   There is no runtime check (unlike Python's bignums). Property
--                  tests that compare against `Integer`, or `-Wall` plus review of
--                  every `Int` doing unbounded arithmetic, are the defense.
-- THE FIX:         Use `Integer` for unbounded results. It is arbitrary precision
--                  and never overflows. Reserve `Int` for indices and sizes.
--
-- Requires GHC (not installed in this build env). Run with:  runghc 01_int_overflow.hs
--
-- EXPECTED OUTPUT (numerics verified against a 64-bit two's-complement model):
--   maxBound :: Int            = 9223372036854775807
--   (maxBound :: Int) + 1      = -9223372036854775808     <- wrapped to minBound
--   factorial 20 :: Int        = 2432902008176640000      (still fits, correct)
--   factorial 21 :: Int        = -4249290049419214848     <- NEGATIVE orderings!
--   factorial 66 :: Int        = 0                         <- a "tidy" wrong answer
--   factorial 66 :: Integer    = 544344939077443064003729240247842752644293064388798874532860126869671081148416000000000000000

factorialInt :: Int -> Int
factorialInt n = product [1 .. n]

factorialInteger :: Integer -> Integer
factorialInteger n = product [1 .. n]

main :: IO ()
main = do
    putStrLn $ "maxBound :: Int         = " ++ show (maxBound :: Int)
    putStrLn $ "(maxBound :: Int) + 1   = " ++ show ((maxBound :: Int) + 1)
    putStrLn $ "factorial 20 :: Int     = " ++ show (factorialInt 20)
    putStrLn $ "factorial 21 :: Int     = " ++ show (factorialInt 21)
    putStrLn $ "factorial 66 :: Int     = " ++ show (factorialInt 66)
    putStrLn $ "factorial 66 :: Integer = " ++ show (factorialInteger 66)
    putStrLn ""
    putStrLn ">>> BUG: factorial 21 reports a NEGATIVE count and factorial 66"
    putStrLn "    reports 0 -- both are silent Int overflow. Integer is exact."
    putStrLn "    Fix: factorial :: Integer -> Integer"
