;;;; Entry points for the Makefile. Needs Quicklisp, loaded from ~/.sbclrc.

(defparameter *root*
  (uiop:pathname-parent-directory-pathname
   (uiop:pathname-directory-pathname *load-truename*)))

(push *root* asdf:*central-registry*)

(defun build-binary (system output)
  "Save SYSTEM as the executable OUTPUT. The binary's exit code comes from
the MAIN function in the package named after SYSTEM."
  (ql:quickload system :silent t)
  (let ((main (uiop:find-symbol* "MAIN" (string-upcase system)))
        (path (merge-pathnames output *root*)))
    (ensure-directories-exist path)
    (sb-ext:save-lisp-and-die
     path
     :executable t
     :toplevel (lambda ()
                 (sb-ext:disable-debugger)
                 (sb-ext:exit :code (funcall main))))))

(defun run-tests ()
  "Run the test suite and exit non-zero if any test fails."
  (ql:quickload "dakusui/test" :silent t)
  (uiop:quit (if (uiop:symbol-call "DAKUSUI/TEST" "RUN-TESTS") 0 1)))
