(ns simple.sign
  (:require [clojure.java.io :refer [reader] :as io])
  (:import (java.security Signature KeyFactory Security)
           (java.security.cert CertificateFactory)
           (java.security.spec X509EncodedKeySpec PKCS8EncodedKeySpec)
           (java.io DataInputStream File FileInputStream)
           (java.io InputStreamReader)
           (java.nio.charset Charset)
           (java.nio.file Files)
           (java.time ZonedDateTime ZoneId)
           (java.time.format DateTimeFormatter)
           (java.time.temporal TemporalAccessor)
           (java.time Duration LocalDateTime OffsetDateTime)
           (org.bouncycastle.jce.provider BouncyCastleProvider)
           (org.bouncycastle.util.io.pem PemReader)
           (org.bouncycastle.openssl PEMParser)))


(Security/addProvider (BouncyCastleProvider.))

(def ^:private GMT (ZoneId/of "GMT"))

(def ^:private US-ASCII (Charset/forName "US-ASCII"))

(defn- now []
  (ZonedDateTime/now GMT))

(defn- rfc1123-date [^TemporalAccessor time]
  (.format DateTimeFormatter/RFC_1123_DATE_TIME time))

(def pubkey-file "test-keys/pubkey.pem")
(def privkey-file "test-keys/privkey-open.pem")

(defn load-pubkey [filename]
  (let [factory (KeyFactory/getInstance "RSA" "BC")
        spec (with-open [pemReader (PemReader. (reader (io/resource filename)))]
               (-> (.readPemObject pemReader)
                   (.getContent)
                   (X509EncodedKeySpec.)))]
    (.generatePublic factory spec)))

(defn load-private-key [filename]
  (let [factory (KeyFactory/getInstance "RSA" "BC")
        spec (with-open [parser (-> (io/input-stream (io/resource filename))
                                    (InputStreamReader. "US-ASCII")
                                    (PEMParser.))]
               (-> (.readPemObject parser)
                   (.getContent)
                   (PKCS8EncodedKeySpec.)))]
    (.generatePrivate factory spec)))

(defn verify [pubkey date doc sig]
  (let [result (.verify (doto (Signature/getInstance "SHA256withRSA")
                          (.initVerify pubkey)
                          (.update (.getBytes date "US-ASCII"))
                          (.update doc))
                        sig)]
    (println "verify result:" result)
    result))

(defn sign [private-key ^String date ^bytes doc]
  (.sign (doto (Signature/getInstance "SHA256withRSA")
           (.initSign private-key)
           (.update (.getBytes date US-ASCII))
           (.update doc))))
