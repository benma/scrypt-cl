import qualified System.IO as IO
import Control.Exception (bracket_)
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Lazy as BSL
import Crypto.Scrypt

import qualified Options.Applicative as O
import Data.Monoid ((<>))
import Control.Applicative ((<$>), (<*>))
import Data.Word (Word64)
import qualified Data.Binary.Put as BinP
import System.Posix (queryTerminal, stdInput)


type SaltSeed = Word64
saltFromWord64 :: SaltSeed -> BS.ByteString
saltFromWord64 = BSL.toStrict . BinP.runPut . BinP.putWord64le


data Options = Options { _logN :: Integer
                       , _r :: Integer
                       , _p :: Integer
                       , _saltSeed :: SaltSeed
                       , _keySize :: Integer
                       , _base64 :: Bool
                       }

main :: IO ()
main = do
  Options logN r p saltSeed keySize base64 <- O.execParser parserInfo
  case scryptParamsLen logN r p keySize of
    Nothing -> error "invalid scrypt parameters"
    Just params -> do
      isInteractive <- queryTerminal stdInput -- is stdin user terminal input (and not pipe or file)?
      key <- if isInteractive
             then BC.pack <$> getKey
             else BS.getContents
      let PassHash derivedKey = scrypt params (Salt $ saltFromWord64 saltSeed) (Pass key)
      if base64
        then BS.putStr $ B64.encode derivedKey
        else BS.putStr derivedKey
  where
    parserInfo = O.info (O.helper <*> parser) (O.progDesc "Scrypt takes three tuning parameters: N, r and p. They affect running time and memory usage: memory usage is approximately 128*r*N bytes.\nReference values:\nN = 2^14, r = 8, p = 1: for < 100ms (interactive use)\nN = 2^20, r = 8, p = 1: for < 5s (sensitive storage)\n\nThe output is written to stdout.")
    parser = Options
             <$> O.option (O.long "logN" <> O.help "N is the general work factor, iteration count; linearly proportional to memory usage and running time." <> O.value 14 <> O.showDefault)
             <*> O.option (O.short 'r' <> O.help "Blocksize in use for underlying hash; linearly proportional to memory usage and running time." <> O.value 8 <> O.showDefault)
             <*> O.option (O.short 'p' <> O.help "Parallelization factor; linearly proportional to running time." <> O.value 1 <> O.showDefault)
             <*> O.option (O.long "salt" <> O.help "8 byte given by a 64 bit unsigned integer in little endian.")
             <*> O.option (O.long "size" <> O.help "Size of resulting key in bytes." <> O.value 64 <> O.showDefault)
             <*> O.switch (O.long "base64" <> O.help "Output the derived key in base64 encoding instead of binary.")
    getKey = do
      IO.hPutStr IO.stderr "Key: "
      IO.hFlush IO.stderr
      pass <- bracket_ (IO.hSetEcho IO.stdin False) (IO.hSetEcho IO.stdin True) IO.getLine
      IO.hPutChar IO.stderr '\n'
      return pass
