(ns simple.encrypt
  (:require [buddy.core.hash :as hash]
            [buddy.core.codecs :as codecs]
            [buddy.core.nonce :as nonce]
            [buddy.core.crypto :as crypto]
            [cheshire.core :as json])
  )

(defn generate-iv
  [len]
  (nonce/random-bytes len))

(defn hmac-sha256-encrypt
  [^String key
   ^bytes iv
   ^String string-to-encrypt]
  (let [original-text (codecs/to-bytes string-to-encrypt)
        key-bytes (hash/sha256 key)]
    (crypto/encrypt original-text key-bytes iv
                    {:algorithm :aes128-cbc-hmac-sha256})))

(defn hmac-sha256-decrypt
  [^String key
   ^bytes iv
   ^bytes encrypted-data]
  (let [key-bytes (hash/sha256 key)]
    (-> (crypto/decrypt encrypted-data key-bytes iv
                        {:algorithm :aes128-cbc-hmac-sha256})
        (codecs/bytes->str))))