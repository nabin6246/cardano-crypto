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

module Mnemonic
    (
      SomeMnemonic(..)
    , MkSomeMnemonic (..)
    , MkSomeMnemonicError(..)
    , someMnemonicToBytes
    , NatVals (..)

      -- * @Mnemonic@
    , Mnemonic
    , mkMnemonic
    , MkMnemonicError(..)
    , mnemonicToText
    , mnemonicToEntropy

      -- * @Entropy@
    , Entropy
    , genEntropy
    , mkEntropy
    , entropyToBytes
    , entropyToMnemonic

      -- Internals & Re-export from @Crypto.Encoding.BIP39@
    , EntropyError(..)
    , DictionaryError(..)
    , MnemonicWordsError(..)
    , ValidEntropySize
    , ValidChecksumSize
    , ValidMnemonicSentence
    , ConsistentEntropy
    , CheckSumBits
    , EntropySize
    , MnemonicWords
    , MnemonicException(..)

      -- * Troubleshooting
      -- $troubleshooting
    ) where

import Prelude

import Basement.NormalForm
    ( NormalForm (..) )
import Basement.Sized.List
    ( unListN )
import Control.Arrow
    ( left )
import Control.DeepSeq
    ( NFData (..) )
import Control.Monad.Catch
    ( throwM )
import Crypto.Encoding.BIP39
    ( CheckSumBits
    , ConsistentEntropy
    , DictionaryError (..)
    , Entropy
    , EntropyError (..)
    , EntropySize
    , MnemonicSentence
    , MnemonicWords
    , MnemonicWordsError (..)
    , ValidChecksumSize
    , ValidEntropySize
    , ValidMnemonicSentence
    , dictionaryIndexToWord
    , entropyRaw
    , entropyToWords
    , mnemonicPhrase
    , mnemonicPhraseToMnemonicSentence
    , mnemonicSentenceToListN
    , toEntropy
    , wordsToEntropy
    )
import Data.Bifunctor
    ( bimap )
import Data.ByteArray
    ( ScrubbedBytes )
import Data.List
    ( intercalate )
import Data.Proxy
    ( Proxy (..) )
import Data.Text
    ( Text )
import Data.Type.Equality
    ( (:~:) (..), testEquality )
import Data.Typeable
    ( Typeable )
import GHC.TypeLits
    ( KnownNat, Nat, natVal )
import Type.Reflection
    ( typeOf )

import qualified Basement.Compat.Base as Basement
import qualified Basement.String as Basement
import qualified Crypto.Encoding.BIP39.English as Dictionary
import qualified Crypto.Random.Entropy as Crypto
import qualified Data.ByteArray as BA
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString.Char8 as B8

--From cardano-address

-- A opaque 'Mnemonic' type.
data Mnemonic (mw :: Nat) = Mnemonic
    { mnemonicToEntropy  :: Entropy (EntropySize mw)
        -- ^ Convert a 'Mnemonic' back to an 'Entropy'.
        --
        -- @since 1.0.0
    , mnemonicToSentence :: MnemonicSentence mw
    } deriving stock (Eq, Show)

-- This wraps EntropyError of "Cardano.Encoding.BIP39"
newtype MnemonicException csz =
    UnexpectedEntropyError (EntropyError csz)
    -- ^ Invalid entropy length or checksum
    deriving stock (Show, Typeable)
    deriving newtype NFData

-- | This wraps errors from "Cardano.Encoding.BIP39"
data MkMnemonicError csz
    = ErrMnemonicWords MnemonicWordsError
      -- ^ Wrong number of words in mnemonic.
    | ErrEntropy (EntropyError csz)
      -- ^ Invalid entropy length or checksum.
    | ErrDictionary DictionaryError
      -- ^ Invalid word in mnemonic.
    deriving stock (Eq, Show)

deriving instance Eq (EntropyError czs)
deriving instance Eq MnemonicWordsError
deriving instance Eq DictionaryError

-- NFData instances
instance NFData (Mnemonic mw) where
    rnf (Mnemonic ent ws) = toNormalForm ent `seq` toNormalForm ws
instance NFData (EntropyError csz) where
    rnf (ErrInvalidEntropyLength a b) = rnf a `seq` rnf b
    rnf (ErrInvalidEntropyChecksum a b) = toNormalForm a `seq` toNormalForm b
instance NFData MnemonicWordsError where
    rnf (ErrWrongNumberOfWords a b) = rnf a `seq` rnf b
instance NFData DictionaryError where
    rnf (ErrInvalidDictionaryWord s) = toNormalForm s
instance NFData (MkMnemonicError csz) where
    rnf (ErrMnemonicWords e) = rnf e
    rnf (ErrEntropy e) = rnf e
    rnf (ErrDictionary e) = rnf e

-- | Smart-constructor for the 'Entropy'. Make sure the 'ByteString' comes from a highly random source or use 'genEntropy'.
--
-- __example__:
--
-- >>> mkEntropy @160 bytes
-- Entropy {} :: Entropy 160
--
-- __property__:
--
-- prop> mkEntropy (entropyToBytes ent) == Right ent
--
-- @since 1.0.0
mkEntropy
    :: forall (ent :: Nat) csz. (ValidEntropySize ent, ValidChecksumSize ent csz)
    => ScrubbedBytes
    -> Either (EntropyError csz) (Entropy ent)
mkEntropy = toEntropy

-- | Generate Entropy of a given size using a cryptographically secure random seed.
--
-- __example:__
--
-- >>> genEntropy @128
-- Entropy {} :: Entropy 128
--
-- @since 1.0.0
genEntropy
    :: forall (ent :: Nat) csz. (ValidEntropySize ent, ValidChecksumSize ent csz)
    => IO (Entropy ent)
genEntropy =
    let
        size =
            fromIntegral $ natVal @ent Proxy
        eitherToIO =
            either (throwM . UnexpectedEntropyError) return
    in
        (eitherToIO . mkEntropy) =<< Crypto.getEntropy (size `div` 8)

-- | Smart-constructor for 'Mnemonic'. Requires a type application to
-- disambiguate the mnemonic size.
--
-- __example__:
--
-- >>> mkMnemonic @15 sentence
-- Mnemonic {} :: Mnemonic 15
--
-- __property__:
--
-- prop> mkMnemonic (mnemonicToText mnemonic) == Right mnemonic
--
-- @since 1.0.0
mkMnemonic
    :: forall (mw :: Nat) (ent :: Nat) csz.
     ( ConsistentEntropy ent mw csz
     , EntropySize mw ~ ent
     )
    => [Text]
    -> Either (MkMnemonicError csz) (Mnemonic mw)
mkMnemonic wordsm = do
    phrase <- left ErrMnemonicWords
        $ mnemonicPhrase @mw (toUtf8String <$> wordsm)

    sentence <- left ErrDictionary
        $ mnemonicPhraseToMnemonicSentence Dictionary.english phrase

    entropy <- left ErrEntropy
        $ wordsToEntropy sentence

    pure Mnemonic
        { mnemonicToEntropy  = entropy
        , mnemonicToSentence = sentence
        }

-- | Convert an Entropy to a corresponding Mnemonic Sentence. Since 'Entropy'
-- and 'Mnemonic' can only be created through smart-constructors, this function
-- cannot fail and is total.
--
-- @since 1.0.0
entropyToMnemonic
    :: forall mw ent csz.
     ( ValidMnemonicSentence mw
     , ValidEntropySize ent
     , ValidChecksumSize ent csz
     , ent ~ EntropySize mw
     , mw ~ MnemonicWords ent
     )
    => Entropy ent
    -> Mnemonic mw
entropyToMnemonic entropy = Mnemonic
    { mnemonicToSentence = entropyToWords entropy
    , mnemonicToEntropy  = entropy
    }

-- | Convert 'Entropy' to plain bytes.
--
-- @since 1.0.0
entropyToBytes
    :: Entropy n
    -> ScrubbedBytes
entropyToBytes = BA.convert . entropyRaw

toUtf8String
    :: Text
    -> Basement.String
toUtf8String = Basement.fromString . T.unpack

fromUtf8String
    :: Basement.String
    -> Text
fromUtf8String = T.pack . Basement.toList

instance (KnownNat csz) => Basement.Exception (MnemonicException csz)

-- | Convert a 'Mnemonic' to a sentence of English mnemonic words.
--
-- @since 1.0.0
mnemonicToText
    :: Mnemonic mw
    -> [Text]
mnemonicToText =
    map (fromUtf8String . dictionaryIndexToWord Dictionary.english)
    . unListN
    . mnemonicSentenceToListN
    . mnemonicToSentence

-- | Convert a 'SomeMnemonic' to bytes.
--
-- @since 1.0.1
someMnemonicToBytes :: SomeMnemonic -> ScrubbedBytes
someMnemonicToBytes (SomeMnemonic mw) = entropyToBytes $ mnemonicToEntropy mw

-- | Ease the manipulation of 'Mnemonic' by encapsulating the type constraints inside a constructor.
-- This is particularly useful for functions which do not require anything but a valid 'Mnemonic' without any
-- particular pre-condition on the size of the 'Mnemonic' itself.
--
-- @since 1.0.0
data SomeMnemonic where
    SomeMnemonic :: forall mw. KnownNat mw => Mnemonic mw -> SomeMnemonic

deriving instance Show SomeMnemonic
instance Eq SomeMnemonic where
    (SomeMnemonic mwa) == (SomeMnemonic mwb) =
        case typeOf mwa `testEquality` typeOf mwb of
            Nothing -> False
            Just Refl -> mwa == mwb
instance NFData SomeMnemonic where
    rnf (SomeMnemonic mnem) = rnf mnem

-- | This class enables caller to parse text list of variable length
-- into mnemonic sentences.
--
-- Note that the given 'Nat's **have** to be valid mnemonic sizes, otherwise the
-- underlying code won't even compile, with not-so-friendly error messages.
class MkSomeMnemonic (sz :: [Nat]) where
    -- | Construct a mnemonic from a list of words. This function is particularly useful when the
    -- number of words is not necessarily known at runtime. The function is however /ambiguous/ and
    -- requires thereby a type application.
    --
    -- __examples:__
    --
    -- >>> mkSomeMnemonic @'[ 12 ] [ "test", "child", "burst", "immense", "armed", "parrot", "company", "walk", "dog" ]
    -- Left "Invalid number of words: 12 words are expected."
    --
    -- >>> mkSomeMnemonic @'[ 9, 12, 15 ] [ "test", "child", "burst", "immense", "armed", "parrot", "company", "walk", "dog" ]
    -- Right (SomeMnemonic ...)
    --
    -- @since 1.0.0
    mkSomeMnemonic :: [Text] -> Either (MkSomeMnemonicError sz) SomeMnemonic

-- | Error reported from trying to create a passphrase from a given mnemonic
--
-- @since 1.0.0
newtype MkSomeMnemonicError (sz :: [Nat]) =
    MkSomeMnemonicError { getMkSomeMnemonicError :: String }
    deriving stock (Eq, Show)

instance {-# OVERLAPS #-}
    ( n ~ EntropySize mw
    , csz ~ CheckSumBits n
    , ConsistentEntropy n mw csz
    , MkSomeMnemonic rest
    , NatVals rest
    ) =>
    MkSomeMnemonic (mw ': rest)
  where
    mkSomeMnemonic parts = case parseMW of
        Left err -> left (promote err) parseRest
        Right mw -> Right mw
      where
        parseMW = left (MkSomeMnemonicError . getMkSomeMnemonicError) $ -- coerce
            mkSomeMnemonic @'[mw] parts
        parseRest = left (MkSomeMnemonicError . getMkSomeMnemonicError) $ -- coerce
            mkSomeMnemonic @rest parts
        promote e e' =
            let
                sz = fromEnum <$> natVals (Proxy :: Proxy (mw ': rest))
                mw = fromEnum $ natVal (Proxy :: Proxy mw)
            in if length parts `notElem` sz
                then MkSomeMnemonicError
                    $  "Invalid number of words: "
                    <> intercalate ", " (show <$> init sz)
                    <> (if length sz > 1 then " or " else "") <> show (last sz)
                    <> " words are expected."
                else if length parts == mw then e else e'

-- | Small helper to collect 'Nat' values from a type-level list
class NatVals (ns :: [Nat]) where
    natVals :: Proxy ns -> [Integer]

instance NatVals '[] where
    natVals _ = []

instance (KnownNat n, NatVals rest) => NatVals (n ': rest) where
    natVals _ = natVal (Proxy :: Proxy n) : natVals (Proxy :: Proxy rest)

instance
    ( n ~ EntropySize mw
    , csz ~ CheckSumBits n
    , ConsistentEntropy n mw csz
    ) =>
    MkSomeMnemonic (mw ': '[])
  where
    mkSomeMnemonic parts = do
        bimap (MkSomeMnemonicError . pretty) SomeMnemonic (mkMnemonic @mw parts)
      where
        pretty = \case
            ErrMnemonicWords ErrWrongNumberOfWords{} ->
                "Invalid number of words: "
                <> show (natVal (Proxy :: Proxy mw))
                <> " words are expected."
            ErrDictionary (ErrInvalidDictionaryWord _) ->
                "Found an unknown word not present in the pre-defined dictionary. \
                \The full dictionary is available here: \
                \https://github.com/input-output-hk/cardano-wallet/tree/master/specifications/mnemonic/english.txt"
            ErrEntropy ErrInvalidEntropyChecksum{} ->
                "Invalid entropy checksum: please double-check the last word of \
                \your mnemonic sentence."
            ErrEntropy ErrInvalidEntropyLength{} ->
                "Something went wrong when trying to generate the entropy from \
                \the given mnemonic. As a user, there's nothing you can do."

                