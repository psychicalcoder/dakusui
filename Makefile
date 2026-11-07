SBCL := sbcl --noinform --non-interactive --load scripts/tools.lisp
SOURCES := dakusui.asd scripts/tools.lisp $(shell find src -name '*.ct')

.PHONY: build test clean
# Each build compiles the shared systems, so builds must not race.
.NOTPARALLEL:
.DELETE_ON_ERROR:

build: build/dakusui build/dakusui-agent

build/dakusui: $(SOURCES)
	$(SBCL) --eval '(build-binary "dakusui/helper" "$@")'

build/dakusui-agent: $(SOURCES)
	$(SBCL) --eval '(build-binary "dakusui/agent" "$@")'

test:
	$(SBCL) --eval '(run-tests)'

clean:
	rm -rf build
