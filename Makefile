.PHONY: test clean rpm

MODULE := pam_jwt

build:
	go build -buildmode=c-shared -o $(MODULE).so

clean:
	rm -f $(MODULE).so $(MODULE).h
