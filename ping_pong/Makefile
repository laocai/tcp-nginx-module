SUBDIRS = cli svr

pp:
	for dir in $(SUBDIRS);do\
		$(MAKE) -C $$dir;\
	done

.PHONY: clean
clean:
	for dir in $(SUBDIRS);do\
		$(MAKE) clean -C $$dir;\
	done

