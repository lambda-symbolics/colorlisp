(in-package #:colorlisp)

(defvar *native-probe-loader-library* nil
  "Process-lifetime CFFI registration of the Windows system loader API.")

(defun colorlisp--unsigned (bytes offset &optional (count 2))
  "Read COUNT little-endian octets from BYTES at OFFSET."
  (loop for index below count
        sum (ash (aref bytes (+ offset index)) (* index 8))))

(defun native-validate-windows-image (pathname)
  "Require an x64 PE32+ DLL at PATHNAME and return its pathname.
This explicit Windows artifact check does not apply to normal library selection."
  (with-open-file (stream pathname :element-type '(unsigned-byte 8))
    (let ((dos (make-array 64 :element-type '(unsigned-byte 8)))
          (pe  (make-array 26 :element-type '(unsigned-byte 8))))
      (unless (and (= (read-sequence dos stream) 64)
                   (= (colorlisp--unsigned dos 0) #x5a4d))
        (error 'highlight-error
               :detail (format nil "ColorLisp library is not a PE image: ~A" pathname)))
      (let ((offset (colorlisp--unsigned dos 60 4)))
        (unless (and (<= 64 offset (- (file-length stream) 26))
                     (file-position stream offset)
                     (= (read-sequence pe stream) 26)
                     (= (colorlisp--unsigned pe 0 4) #x4550)
                     (= (colorlisp--unsigned pe 4) #x8664)
                     (>= (colorlisp--unsigned pe 20) 2)
                     (logtest #x2000 (colorlisp--unsigned pe 22))
                     (= (colorlisp--unsigned pe 24) #x20b))
          (error 'highlight-error
                 :detail (format nil "ColorLisp library is not an x64 PE32+ DLL: ~A"
                                 pathname))))))
  (pathname pathname))

(defun colorlisp--probe-session (symbols &key language source query number-p)
  "Exercise one exact-handle session with LANGUAGE, SOURCE and QUERY.
When NUMBER-P is true, require a number capture over the literal 42."
  (flet ((symbol-pointer (name)
           "Return the already resolved pointer for NAME."
           (rest (assoc name symbols :test #'string=))))
    (cffi:with-foreign-string (source-pointer source :encoding :utf-8)
      (cffi:with-foreign-string (query-pointer query :encoding :utf-8)
        (cffi:with-foreign-objects ((error-offset :uint32) (error-type :uint32)
                                    (pattern :uint32) (count :uint32)
                                    (capture :uint32) (start :uint32) (end :uint32)
                                    (name-length :uint32))
          (let ((session
                  (cffi:foreign-funcall-pointer (symbol-pointer "colorlisp_session_new") ()
                    :string language :pointer source-pointer :uint32 (length source)
                    :pointer query-pointer :uint32 (length query)
                    :pointer error-offset :pointer error-type :pointer))
                (found nil))
            (when (cffi:null-pointer-p session)
              (error 'highlight-error
                     :detail (format nil "Native ~A probe session failed (~D at ~D)."
                                     language (cffi:mem-ref error-type :uint32)
                                     (cffi:mem-ref error-offset :uint32))))
            (unwind-protect
                 (progn
                   (loop while
                         (cffi:foreign-funcall-pointer
                             (symbol-pointer "colorlisp_session_next_match") ()
                           :pointer session :pointer pattern :pointer count :boolean)
                         do (loop for index below (cffi:mem-ref count :uint32)
                                  do (unless
                                         (cffi:foreign-funcall-pointer
                                             (symbol-pointer "colorlisp_session_capture") ()
                                           :pointer session :uint32 index :pointer capture
                                           :pointer start :pointer end :boolean)
                                       (error 'highlight-error :detail "Native capture probe failed."))
                                     (let* ((name-pointer
                                              (cffi:foreign-funcall-pointer
                                                  (symbol-pointer "colorlisp_session_capture_name") ()
                                                :pointer session
                                                :uint32  (cffi:mem-ref capture :uint32)
                                                :pointer name-length :pointer))
                                            (name (colorlisp--foreign-string
                                                   name-pointer
                                                   (cffi:mem-ref name-length :uint32))))
                                       (when (and (string= name "number")
                                                  (= (cffi:mem-ref start :uint32)
                                                     (or (search "42" source) -1))
                                                  (= (cffi:mem-ref end :uint32)
                                                     (+ 2 (or (search "42" source) -1))))
                                         (setf found t)))))
                   (when (and number-p (not found))
                     (error 'highlight-error
                            :detail (format nil "Native ~A number-span probe failed." language))))
              (cffi:foreign-funcall-pointer (symbol-pointer "colorlisp_session_delete") ()
                :pointer session :void))))))))

(defun colorlisp--loader-symbol (name)
  "Resolve a system dynamic-loader entry point named NAME."
  (when (and (uiop:os-windows-p) (null *native-probe-loader-library*))
    (setf *native-probe-loader-library* (cffi:load-foreign-library "kernel32.dll")))
  (let ((pointer (cffi:foreign-symbol-pointer name)))
    (when (or (null pointer) (cffi:null-pointer-p pointer))
      (error 'highlight-error
             :detail (format nil "System dynamic-loader API is unavailable: ~A" name)))
    pointer))

(defun colorlisp--probe-open (pathname)
  "Open PATHNAME with the OS loader and return its native handle."
  ;; CFFI's SBCL backend ignores the library in foreign-symbol-pointer.
  ;; Use OS handles directly, without SBCL's global shared-object registry.
  (let ((handle
          (if (uiop:os-windows-p)
              (cffi:with-foreign-string (wide (uiop:native-namestring pathname)
                                              :encoding :utf-16le)
                (cffi:foreign-funcall-pointer
                    (colorlisp--loader-symbol "LoadLibraryW") ()
                  :pointer wide :pointer))
              (cffi:foreign-funcall-pointer
                  (colorlisp--loader-symbol "dlopen") ()
                :string (uiop:native-namestring pathname) :int 2 :pointer))))
    (when (cffi:null-pointer-p handle)
      (error 'highlight-error
             :detail (format nil "Could not open native artifact: ~A" pathname)))
    handle))

(defun colorlisp--probe-symbol (handle name)
  "Resolve NAME against HANDLE rather than globally loaded libraries."
  (cffi:foreign-funcall-pointer
      (colorlisp--loader-symbol (if (uiop:os-windows-p) "GetProcAddress" "dlsym")) ()
    :pointer handle :string name :pointer))

(defun colorlisp--probe-close (handle)
  "Release the OS loader reference acquired for HANDLE."
  (cffi:foreign-funcall-pointer
      (colorlisp--loader-symbol (if (uiop:os-windows-p) "FreeLibrary" "dlclose")) ()
    :pointer handle :int))

(defun native-probe (pathname &key windows-image-p)
  "Load and exercise exactly PATHNAME, independent of any previously loaded library.
Resolve the complete ColorLisp API against this handle, then check incomplete
Common Lisp input and Common Lisp/Rust number spans. Optionally check the x64
PE32+ DLL header before loading. Return the absolute tested pathname."
  (let ((path (merge-pathnames pathname (uiop:getcwd))))
    (when windows-image-p
      (native-validate-windows-image path))
    (let ((library (colorlisp--probe-open path)))
      (unwind-protect
           (let ((symbols
                   (loop for name in '("colorlisp_session_new"
                                       "colorlisp_session_delete"
                                       "colorlisp_session_next_match"
                                       "colorlisp_session_capture"
                                       "colorlisp_session_capture_name"
                                       "colorlisp_session_predicate_step_count"
                                       "colorlisp_session_predicate_step"
                                       "colorlisp_session_string_value")
                         for pointer = (colorlisp--probe-symbol library name)
                         do (when (or (null pointer) (cffi:null-pointer-p pointer))
                              (error 'highlight-error
                                     :detail (format nil "Missing ColorLisp API: ~A" name)))
                         collect (cons name pointer))))
             (colorlisp--probe-session symbols :language "commonlisp" :source "("
                                      :query "(num_lit) @number")
             (colorlisp--probe-session symbols
                                      :language "commonlisp"
                                      :source   "(defun answer () 42)"
                                      :query    "(num_lit) @number" :number-p t)
             (colorlisp--probe-session symbols
                                      :language "rust"
                                      :source   "fn main() { 42 }"
                                      :query    "(integer_literal) @number" :number-p t)
             path)
        (colorlisp--probe-close library)))))
