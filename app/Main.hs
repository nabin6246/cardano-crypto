{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# OPTIONS_HADDOCK prune #-}

module Main
    (
        main,
    ) where

import Crypto.Encoding.BIP39
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString.Char8 as B8
import Mnemonic


main :: IO ()
main = do
    putStrLn "ok"
    m <- mnemonicToText @15 . entropyToMnemonic <$> genEntropy
    B8.putStrLn $ TE.encodeUtf8 $ T.unwords m
--   seed <- getRandomBytes 32 :: IO Bytes
--   let rootXprv = generate seed noPass
--   let child1Xprv = deriveXPrv DerivationScheme2 noPass rootXprv hardIdx
--   -- let words = entropyToWords (Entropy 128)
--   putStrLn $ "Testing" ++ show (unXPrv rootXprv)
--   putStrLn $ "Testing" ++ show (unXPrv child1Xprv)


-- noPass :: Bytes
-- noPass = B.empty


-- hardIdx :: DerivationIndex
-- hardIdx = 0x80000001




-- genEntropy
--     :: forall (ent :: Nat) csz. (ValidEntropySize ent, ValidChecksumSize ent csz, GHC.Exception.Type.Exception (MnemonicException csz))
--     => IO (Entropy ent)
-- genEntropy =
--     let
--         size =
--             fromIntegral $ natVal @ent Proxy
--         eitherToIO =
--             either (throwM . UnexpectedEntropyError) return
--     in
--         (eitherToIO . mkEntropy) =<< Crypto.getEntropy (size `div` 8)

-- -- This wraps EntropyError of "Cardano.Encoding.BIP39"
-- newtype MnemonicException csz =
--     UnexpectedEntropyError (EntropyError csz)
--     -- ^ Invalid entropy length or checksum
--     deriving stock (Show, Typeable)
--     deriving newtype NFData

-- deriving instance Eq (EntropyError czs)

-- instance NFData (EntropyError csz) where
--     rnf (ErrInvalidEntropyLength a b) = rnf a `seq` rnf b
--     rnf (ErrInvalidEntropyChecksum a b) = toNormalForm a `seq` toNormalForm b

-- mkEntropy
--     :: forall (ent :: Nat) csz. (ValidEntropySize ent, ValidChecksumSize ent csz)
--     => ScrubbedBytes
--     -> Either (EntropyError csz) (Entropy ent)
-- mkEntropy = toEntropy