(ns simple.wechat
  (:require [buddy.core.padding :as padding]
            [buddy.core.bytes :as bytes]
            [buddy.core.hash :as hash]
            [buddy.core.codecs :as codecs]
            [buddy.core.codecs.base64 :as base64]
            [buddy.core.crypto :as crypto]))

(defn verify-signature [session-key raw-data signature]
  (= signature
     (-> (str raw-data session-key)
         hash/sha1
         codecs/bytes->hex)))

(comment
  (let [raw-data "{\"nickName\":\"Band\",\"gender\":1,\"language\":\"zh_CN\",\"city\":\"Guangzhou\",\"province\":\"Guangdong\",\"country\":\"CN\",\"avatarUrl\":\"http://wx.qlogo.cn/mmopen/vi_32/1vZvI39NWFQ9XM4LtQpFrQJ1xlgZxx3w7bQxKARol6503Iuswjjn6nIGBiaycAjAtpujxyzYsrztuuICqIM5ibXQ/0\"}"
        session-key "HyVFkGl5F5OQWJZZaNzBBg=="
        signature "75e81ceda165f4ffa64f4068af58c64b8f54b88c"]
    (verify-signature session-key raw-data signature)))


(defn decrypt-data
  [session-key encrypted-data iv]
  (let [eng (crypto/block-cipher :aes :cbc)
        aeskey (base64/decode session-key)
        encrypted-data (base64/decode encrypted-data)
        iv (base64/decode iv)]
    (crypto/decrypt-cbc eng encrypted-data aeskey iv) ; This is a buddy.core.crypto internal api, it might not be supported in future version.
    ))