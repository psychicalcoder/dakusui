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

(defsystem "dakusui/attach-check"
  :description "A check that needs capabilities. Run it with `make attach-check`."
  :depends-on ("coalton" "cffi" "dakusui/policy" "dakusui/helper")
  :defsystem-depends-on ("coalton-asdf")
  :pathname "test/"
  :components ((:ct-file "attach-check")))

(defsystem "dakusui/helper"
  :description "The dakusui binary: holds the capabilities and owns the BPF maps."
  :depends-on ("coalton" "cffi" "sb-posix" "com.inuoe.jzon" "dakusui/policy")
  :defsystem-depends-on ("coalton-asdf")
  :pathname "src/helper/"
  :serial t
  :components ((:ct-file "libbpf")
               (:ct-file "pins")
               (:ct-file "enforcer")
               (:ct-file "cleanup")
               (:ct-file "spawn")
               (:ct-file "protocol")
               (:ct-file "serve")
               (:ct-file "main")))

(defsystem "dakusui/agent"
  :description "The dakusui-agent binary: runs the LLM loop and owns the policy."
  :depends-on ("coalton" "cffi" "com.inuoe.jzon" "dakusui/policy")
  :defsystem-depends-on ("coalton-asdf")
  :pathname "src/agent/"
  :serial t
  :components ((:ct-file "chat")
               (:ct-file "terminal")
               (:ct-file "client")
               (:ct-file "denials")
               (:ct-file "session")
               (:ct-file "launch")
               (:ct-file "tools")
               (:ct-file "mcp")
               (:ct-file "provider")
               (:ct-file "loop")
               (:ct-file "gate")
               (:ct-file "rulesets")
               (:ct-file "commands")
               (:ct-file "options")
               (:ct-file "config")
               (:ct-file "main")))

(defsystem "dakusui/check-agent"
  :description "The acceptance harness: a stand-in agent that runs A1 through
A19, the random-policy test, the torn-walk test, and spec 0003 A3, A4, A6, A9,
and A10 under the real helper.
Run it with `make attach-check`."
  :depends-on ("coalton" "cffi" "dakusui/policy" "dakusui/agent")
  :defsystem-depends-on ("coalton-asdf")
  :pathname "test/"
  :serial t
  :components ((:ct-file "check-agent")
               (:ct-file "check-stress")
               (:ct-file "check-main")))

(defsystem "dakusui/test"
  :description "Unit tests. Run them with `make test`."
  :depends-on ("coalton" "coalton/testing" "fiasco" "sb-bsd-sockets"
               "dakusui/policy" "dakusui/helper" "dakusui/agent")
  :defsystem-depends-on ("coalton-asdf")
  :pathname "test/"
  :serial t
  :components ((:ct-file "suite")
               (:ct-file "policy")
               (:ct-file "parse")
               (:ct-file "evaluate")
               (:ct-file "default")
               (:ct-file "compile")
               (:ct-file "libbpf")
               (:ct-file "spawn")
               (:ct-file "protocol")
               (:ct-file "session")
               (:ct-file "launch")
               (:ct-file "denials")
               (:ct-file "pins")
               (:ct-file "chat")
               (:ct-file "terminal")
               (:ct-file "tools")
               (:ct-file "mcp")
               (:ct-file "loop")
               (:ct-file "gate")
               (:ct-file "provider")
               (:ct-file "commands")
               (:ct-file "options")
               (:ct-file "config")
               (:ct-file "rulesets")
               (:ct-file "wiring")))
