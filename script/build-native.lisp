(require :asdf)

(let ((root (uiop:pathname-parent-directory-pathname
             (uiop:pathname-directory-pathname *load-truename*))))
  ;; Native builds need only ASDF/UIOP, without Quicklisp or the highlighting API.
  (asdf:load-asd (merge-pathnames "colorlisp.asd" root))
  (dolist (file '("src/package.lisp" "src/conditions.lisp" "src/native-build.lisp"))
    (load (merge-pathnames file root))))

(let* ((arguments (uiop:command-line-arguments))
       (kind (cond ((equal (first arguments) "shared") :shared)
                   ((equal (first arguments) "static") :static))))
  (unless (and kind (<= 2 (length arguments) 5))
    (error "Usage: build-native.lisp shared|static OUTPUT [CC [AR [SHARED-FLAG]]]."))
  (apply #'uiop:symbol-call :colorlisp :native-build
         :output (second arguments) :kind kind
         (append (when (third arguments) (list :compiler (third arguments)))
                 (when (fourth arguments) (list :archiver (fourth arguments)))
                 (when (fifth arguments) (list :link-flags (list (fifth arguments)))))))
