package communication

import (
	"net/smtp"
	"strings"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/util"
)

// ConfigSMTP ...
type ConfigSMTP struct {
	Sender   string `json:"sender"`
	UserName string `json:"userName"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     string `json:"port"`
}

// SendEmail ...
func SendEmail(smtpConfig ConfigSMTP, from string, to []string, subject string, body string, cc []string, bcc []string, ch util.GenericChannel) {
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	receivers := strings.Join(to, ",")
	ccReceivers := strings.Join(cc, ",")
	bccReceivers := strings.Join(bcc, ",")
	msg := []byte("To: " + receivers + "\r\n" +
		"cc: " + ccReceivers + "\r\n" +
		"bcc: " + bccReceivers + "\r\n" +
		"Subject: " + subject + "\r\n" +
		mime + "\r\n\r\n" + body + "\r\n")
	socket := smtpConfig.Host + ":" + smtpConfig.Port
	auth := smtp.PlainAuth("", smtpConfig.UserName, smtpConfig.Password, smtpConfig.Host)
	err := smtp.SendMail(socket, auth, from, to, []byte(msg))
	if err != nil {
		ch.Error = err
		ch.Done <- true
		return
	}
	ch.Error = nil
	ch.Done <- true
	return
}
