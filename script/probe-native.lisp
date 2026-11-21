(require :asdf)

(let* ((root (uiop:pathname-parent-directory-pathname
              (uiop:pathname-directory-pathname *load-truename*)))
       (setup (merge-pathnames ".qlot/setup.lisp" root)))
  (if (probe-file setup)
      (load setup)
      (let ((quicklisp (merge-pathnames "quicklisp/setup.lisp"
                                        (user-homedir-pathname))))
        (when (probe-file quicklisp) (load quicklisp))))
  (pushnew root asdf:*central-registry* :test #'equal)
  (asdf:load-asd (merge-pathnames "colorlisp.asd" root))
  (asdf:load-system "colorlisp"))

(let* ((arguments (uiop:command-line-arguments))
       (action (first arguments)))
  (cond
    ((and (equal action "select") (= (length arguments) 1))
     (format t "~&~A~%" (uiop:native-namestring
                         (uiop:symbol-call :colorlisp :native-library-path))))
    ((and (member action '("probe" "warm-probe") :test #'equal)
          (= (length arguments) 2))
     (when (equal action "warm-probe")
       ;; Load the selected good library first to expose global-symbol masking.
       (uiop:symbol-call :colorlisp :highlight-spans "42" :language :common-lisp))
     (uiop:symbol-call :colorlisp :native-probe (second arguments) :windows-image-p t)
     (format t "~&Native artifact probe passed.~%"))
    (t
     (error "Usage: probe-native.lisp select|probe|warm-probe [DLL]."))))
