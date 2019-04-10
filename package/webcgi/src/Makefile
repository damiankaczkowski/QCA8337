
TARGET  := web-cgi

SOURCES := web.c vlan.c switch.c system.c network.c firewall.c statistic.c nmap_scan.c ipsec.c cjson.c utils.c
OBJS    := $(SOURCES:.c=.o)

LDFLAGS += -lm -lconfig -ladapter
IFLAGS += -I. 
CFLAGS += -Os -Wall

all: $(TARGET)
	@echo "Generate cgi."
	@ln -sf /usr/sbin/web-cgi vlan.cgi
	@ln -sf /usr/sbin/web-cgi switch.cgi
	@ln -sf /usr/sbin/web-cgi network.cgi
	@ln -sf /usr/sbin/web-cgi system.cgi
	@ln -sf /usr/sbin/web-cgi firewall.cgi
	@ln -sf /usr/sbin/web-cgi statistic.cgi
	@ln -sf /usr/sbin/web-cgi nmap_scan.cgi
	@ln -sf /usr/sbin/web-cgi ipsec.cgi
	@ln -sf /usr/sbin/web-cgi ipseclog.cgi
	@echo "Generate cli."
	@ln -sf /usr/sbin/web-cgi vlan.cli
	@ln -sf /usr/sbin/web-cgi switch.cli
	@ln -sf /usr/sbin/web-cgi network.cli
	@ln -sf /usr/sbin/web-cgi system.cli
	@ln -sf /usr/sbin/web-cgi firewall.cli
	@ln -sf /usr/sbin/web-cgi statistic.cli
	@ln -sf /usr/sbin/web-cgi nmap_scan.cli
	@ln -sf /usr/sbin/web-cgi ipsec.cli

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	
.c.o:
	$(CC) -c -o $@ $(CFLAGS) $(IFLAGS) $<

clean:
	rm -rf $(TARGET) $(OBJS)

.PHONY: clean
