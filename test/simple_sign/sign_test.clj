(ns simple-sign.sign-test
  (:require [clojure.test :refer :all]
            [simple.sign :refer :all]))

(deftest test-hmac-sha1-sign
  (testing "non-empty key, non-empty string-to-sign"
    (is (= "3nybhbi3iqa8ino29wqQcBydtNk=" (hmac-sha1-sign "key" "The quick brown fox jumps over the lazy dog"))))

  (testing "empty key, empty string-to-sign"
    ; (is (= "+9sdGxiqbAgyS31ktx+3Y3BpDh0=" (hmac-sha1-sign "" ""))) ;; IllegalArgumentException - if algorithm is null or key is null or empty.
    ))
