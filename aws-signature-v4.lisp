
;Request Values

(defvar *http-method*)
(defvar *service*)
(defvar *host*)
(defvar *region*)
(defvar *endpoint*)
(defvar *request-parameters*)

(setf *http-method* "GET")
(setf *service* "ec2")
(setf *host* "example.amazonaws.com")
(setf *region* "us-east-1")
(setf *endpoint* "https://ec2.amazonaws.com")
(setf *request-parameters* "Action=DescribeRegions&Version=2013-10-15")


;Key Derivation Functions

(defun sign (key msg)
  (update-hmac
   (make-hmac (ascii-string-to-byte-array key)
	      'sha256)
   (ascii-string-to-byte-array msg)))

;(defun get-signature-key (key date-stamp region-name service-name)
  ;(sign (concatenate 'string "AWS4" key) (get-date (local-time:now))))

(defun get-signature-key (key date-stamp region-name service-name)
  (byte-array-to-hex-string
   (hmac-digest
    (update-hmac
     (update-hmac
      (update-hmac
       (make-hmac (ascii-string-to-byte-array (concatenate 'string "AWS4" key))
		  'sha256)
       (ascii-string-to-byte-array date-stamp))
      (ascii-string-to-byte-array region-name))
     (ascii-string-to-byte-array service-name)))))


;Read AWS access key from local file into struct

(defvar *credentials*)
(defvar *credentials-file*) ;REMOVE AFTER TESTING

(setf *credentials-file* "~/lisp/cl-aws/credentials-test.csv") ;REMOVE AFTER TESTING

(defstruct aws-credentials username access-key secret-key)

(defun get-aws-credentials (file-name)
      (setf *credentials*
	    (car (cl-csv:read-csv (parse-namestring file-name) :skip-first-p t
				  :map-fn #'(lambda (row)
					      (make-aws-credentials
					       :username (nth 0 row)
					       :access-key (nth 1 row)
					       :secret-key (nth 2 row)))))))
			
(defun get-amz-date (current-time)
  (local-time:format-timestring nil current-time
				:format '(:year (:month 2) (:day 2) "T" (:hour 2) (:min 2) (:sec 2) "Z")))
	  
(defun get-date (current-time)
  (local-time:format-timestring nil current-time
				:format '(:year (:month 2) (:day 2))))

; Create canonical request PART I

(defvar *canonical-uri*)
(defvar *canonical-query-string*)
(defvar *canonical-headers*)
(defvar *signed-headers*)
(defvar *payload-hash*)
(defvar *canonical-request*)

(setf *canonical-uri* "/")

(setf *canonical-query-string* *request-parameters*)

(setf *canonical-headers* 
      (format nil "host:~A~%x-amz-date:~A~%" *host* (get-amz-date (local-time:now))))
(defun get-canonical-headers (current-date)
  (format nil "host:~A~%x-amz-date:~A~%" *host* (get-amz-date current-date)))

(setf *signed-headers* 
      (format nil "host;x-amz-date"))

(setf *payload-hash*
      (sha256-hash ""))

(defun get-canonical-request (http-method canonical-uri canonical-query-string canonical-headers signed-headers payload-hash)
    (format nil
     "~A~%~A~%~A~%~A~%~A~%~A"
     http-method
     canonical-uri
     canonical-query-string
     canonical-headers
     signed-headers
     payload-hash))


; Create the string to sign PART II

(defvar *algorithm*)

(setf *algorithm* "AWS4-HMAC-SHA256")

(defun get-credential-scope ( current-time region service)
      (format nil
	      "~A/~A/~A/~A"
	      (get-date current-time)
	      region
	      service
	      "aws4_request"))

(defun get-string-to-sign (algorithm current-time canonical-request region service)
      (format nil
	      "~A~%~A~%~A~%~A"
	      algorithm
	      (get-amz-date current-time)
	      (get-credential-scope current-time region service)
	      (sha256-hash canonical-request)))


; Calculate the signature PART III

(defun get-signing-key (credentials current-time region service)
      (get-signature-key (aws-credentials-secret-key credentials)
			 (get-date current-time)
			 region
			 service))

(defun get-signature (signing-key)
  (byte-array-to-hex-string
   (hmac-digest
    (make-hmac (ascii-string-to-byte-array signing-key)
	       'sha256))))



; Add signing information to the request PART IV

(defun get-authorization-header (algorithm credentials current-time region service signed-headers)
  (format nil
	  "~A Credential=~A/~A, SignedHeaders=~A, Signature=~A"
	  algorithm
	  (aws-credentials-access-key credentials)
	  (get-credential-scope current-time region service)
	  signed-headers
	  (get-signature (get-signing-key credentials current-time region service))))


; TESTING

(defvar *test-date*)
(defvar *test-region*)
(defvar *test-service*)
(defvar *test-request-parameters*)
(defvar *prefix*)

(setf *test-date* (encode-timestamp 00 00 36 12 30 08 2015))
(setf *test-region* "us-east-1")
(setf *test-service* "service")
(setf *test-request-parameters* "Param1=value1&Param2=value2")
(setf *prefix* "AKIDEXAMPLE")
