;;;; Dakusui's systems. See docs/specs/0001-file-access-policy/plan.md.

;;; Quicklisp finds dakusui/helper through this primary system.
(defsystem "dakusui"
  :description "Everything that ships."
  :depends-on ("dakusui/helper" "dakusui/agent"))

(defsystem "dakusui/policy"
  :description "Policy types, parser, evaluator, and compiler."
  :depends-on ("coalton")
  :defsystem-depends-on ("coalton-asdf")
  :pathname "src/policy/"
  :serial t
  :components ((:ct-file "policy")
               (:ct-file "parse")
               (:ct-file "evaluate")
               (:ct-file "default")
               (:ct-file "compile")))

(defsystem "dakusui/helper"
  :description "The dakusui binary: holds the capabilities and owns the BPF maps."
  :depends-on ("coalton" "dakusui/policy")
  :defsystem-depends-on ("coalton-asdf")
  :pathname "src/helper/"
  :components ((:ct-file "main")))

(defsystem "dakusui/agent"
  :description "The dakusui-agent binary: runs the LLM loop and owns the policy."
  :depends-on ("coalton" "dakusui/policy")
  :defsystem-depends-on ("coalton-asdf")
  :pathname "src/agent/"
  :components ((:ct-file "main")))

(defsystem "dakusui/test"
  :description "Unit tests. Run them with `make test`."
  :depends-on ("coalton" "coalton/testing" "fiasco"
               "dakusui/policy" "dakusui/helper" "dakusui/agent")
  :defsystem-depends-on ("coalton-asdf")
  :pathname "test/"
  :serial t
  :components ((:ct-file "suite")
               (:ct-file "policy")
               (:ct-file "parse")
               (:ct-file "evaluate")
               (:ct-file "default")
               (:ct-file "compile")))
