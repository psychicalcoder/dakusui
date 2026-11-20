;;;; Entry points for the Makefile. Needs Quicklisp, loaded from ~/.sbclrc.

(defparameter *root*
  (uiop:pathname-parent-directory-pathname
   (uiop:pathname-directory-pathname *load-truename*)))

(push *root* asdf:*central-registry*)

(defun build-binary (system output)
  "Save SYSTEM as the executable OUTPUT. The binary's exit code comes from
the MAIN function in the package named after SYSTEM.

The binary takes no SBCL options. :SAVE-RUNTIME-OPTIONS stops the runtime from
reading any, such as --core or --dynamic-space-size, and the toplevel below
replaces the one that reads --eval, --load, and init files. Every argument
reaches MAIN in *POSIX-ARGV*. (T15, R11)"
  (ql:quickload system :silent t)
  (let ((main (uiop:find-symbol* "MAIN" (string-upcase system)))
        (path (merge-pathnames output *root*)))
    (ensure-directories-exist path)
    (sb-ext:save-lisp-and-die
     path
     :executable t
     :save-runtime-options t
     :toplevel (lambda ()
                 (sb-ext:disable-debugger)
                 (sb-ext:exit :code (funcall main))))))

(defun run-tests ()
  "Run the test suite and exit non-zero if any test fails."
  (ql:quickload "dakusui/test" :silent t)
  (uiop:quit (if (uiop:symbol-call "DAKUSUI/TEST" "RUN-TESTS") 0 1)))
