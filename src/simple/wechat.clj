(ns simple.wechat
  (:require [buddy.core.padding :as padding]
            [buddy.core.bytes :as bytes]
            [buddy.core.hash :as hash]
            [buddy.core.codecs :as codecs]
            [buddy.core.codecs.base64 :as base64]
            [buddy.core.crypto :as crypto]
            [cheshire.core :as json])
  (:import (java.nio.charset Charset)
           (java.time ZonedDateTime ZoneId)))

(def ^:private GMT (ZoneId/of "GMT"))
(def ^:private US-ASCII (Charset/forName "US-ASCII"))
(def ^:private UTF-8 (Charset/forName "UTF-8"))

(defn string->utf-8
  [str]
  (. str getBytes UTF-8))

(defn utf-8->string
  [bytes]
  (String. bytes UTF-8))

(defn verify-signature [session-key raw-data signature]
  (= signature
     (-> (str raw-data session-key)
         hash/sha1
         codecs/bytes->hex)))

(defn decrypt-data
  [session-key encrypted-data iv]
  (let [eng (crypto/block-cipher :aes :cbc)
        aeskey (base64/decode session-key)
        encrypted-data (base64/decode encrypted-data)
        iv (base64/decode iv)]
    (-> (crypto/decrypt-cbc eng encrypted-data aeskey iv)
        (utf-8->string)
        (json/parse-string)) ; This is a buddy.core.crypto internal api, it might not be supported in future version.
    ))
