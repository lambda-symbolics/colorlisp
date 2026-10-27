;;;; -- Source Check Tools --

;;; qlot installs a project's dependencies by reading its system definitions.
;;; This system names cheque, the source checker ./script/check loads, so
;;; installing checks/qlfile also installs cheque's own dependencies. Nothing
;;; loads it.

(asdf:defsystem #:colorlisp-check-tools
  :description "The development tools colorlisp's source checks load."
  :depends-on  (#:cheque))
