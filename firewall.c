#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <net/netlink.h> // Für netlink_kernel_create und netlink_unicast
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/list.h> 
#include <linux/string.h>

//netlink protocoll
#define MY_FIREWALL_NETLINK_PROTOCOL 31

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Timon GNU/LINUX");
MODULE_DESCRIPTION("Firewall");


//verschiedene Protokolltypen
typedef enum {
    FW_PROTO_ANY = 0,
    FW_PROTO_TCP,
    FW_PROTO_UDP,
    FW_PROTO_ICMP,
    FW_PROTO_UNKNOWN
} fw_protocol_t;


//portbereich
typedef struct {
    uint16_t start;
    uint16_t end;
} fw_port_range_t;

//verschiedene Actionsmoeglichkeiten
typedef enum {
    FW_ACTION_ACCEPT,
    FW_ACTION_DROP,
    FW_ACTION_REJECT,
    FW_ACTION_UNKWON
} fw_action_t;

// diese befehle sagen den kernel ws er mit dem gesendeten anstellen soll
enum {
    NL_CMD_ADD_RULE = 1,    // Eine Regel hinzufügen
    NL_CMD_DELETE_RULE,     // Eine Regel löschen (nach ID)
    NL_CMD_CLEAR_RULES,     // Alle Regeln löschen
    // Füge weitere Befehle hinzu, wenn du sie brauchst (z.B. GET_RULES, STATUS_REPORT)
};

//firewallregelstruktur
typedef struct firewall_rule_format{
    uint32_t id;
    char name[64];
    bool enabled;
    int priotity;
    int result_code; //so kann ueebrpruft werden vor dem erstellen der linked list ob die struktur gueltig ist

    fw_protocol_t protocoll;

    uint32_t src_ip;    // Host Byte Order
    uint32_t src_mask;  // Host Byte Order
    uint32_t dst_ip;    // Host Byte Order
    uint32_t dst_mask;  // Host Byte Order

    fw_port_range_t src_port; // Host Byte Order
    fw_port_range_t dst_port; // Host Byte Order

    fw_action_t action;
} firewall_rule_format;

//linked list
typedef struct rule_node {
    firewall_rule_format rule;
    struct list_head list;
} rule_node;

// alle globalen variablen
static struct sock *nl_sk = NULL; // Hier wird dein Netlink-Socket-Objekt gespeichert
static LIST_HEAD(firewall_rules_list); // Der Kopf deiner Kernel-Linked-List
static DEFINE_MUTEX(firewall_rules_mutex); // Mutex zum Schutz der Liste

// funktionen
static void netlink_recv_message(struct sk_buff *skb);
//static void send_netlink_ack();
static void clear_list(void);
static int firewall_add_rule(struct firewall_rule_format *received_rule);



static int __init init_firewall(void) {
    printk("Die Firewall wurde erfolgreich geladen\n");

    // zu weisung der callback funktion
    struct netlink_kernel_cfg cfg = {
        .input = netlink_recv_message,
    };

    
    // erstellen des sockets
    nl_sk = netlink_kernel_create(&init_net, MY_FIREWALL_NETLINK_PROTOCOL, &cfg);
    //ueebrpruefen ob das erstellen erfolgreich war
    if (!nl_sk) {
        printk(KERN_ERR "Firewall: Fehler beim Erstellen des Netlink-Sockets.\n");
        return -ENOMEM; // Fehler, wenn es nicht klappt
    }

    printk(KERN_INFO "Firewall: Netlink-Socket erfolgreich erstellt (Protokoll %d).\n", MY_FIREWALL_NETLINK_PROTOCOL);

    return 0;
}

static void __exit exit_firewall(void) {
    printk(KERN_INFO "Firewall: Modul wird entladen.\n"); // KERN_INFO für Logging-Level
    

    // 1. Netlink-Socket freigeben
    if (nl_sk) {
        netlink_kernel_release(nl_sk);
        printk(KERN_INFO "Firewall: Netlink-Socket freigegeben.\n");
    }

    clear_list();

    printk(KERN_INFO "Firewall: Alle Regeln gelöscht. Goodby kernel.\n");


}


// funktion zum loeschen aller linked list elemente
void clear_list() {
    // strukturen fuer das loeschen der listen
    struct rule_node *pos, *next;

    // hier muessen die listen freigegeben werden
    mutex_lock(&firewall_rules_mutex);
    list_for_each_entry_safe(pos, next, &firewall_rules_list, list) {
        printk(KERN_INFO "Firewall: Lösche Regel mit ID %u beim Entladen.\n", pos->rule.id);
        list_del(&pos->list);
        kfree(pos);
    }
    mutex_unlock(&firewall_rules_mutex);
}

void netlink_recv_message(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    int msg_type;
    int pid;

    // herausextrahieren des gesendeten buffers
    nlh = nlmsg_hdr(skb);

    // 2. Extrahiere den Nachrichtentyp und die PID des Senders
    msg_type = nlh->nlmsg_type;
    pid = nlh->nlmsg_pid;

    // Optional: Logge die empfangene Nachricht zur Fehlersuche
    printk(KERN_INFO "Firewall: Nachricht empfangen von PID %d, Typ: %d\n", pid, msg_type);


    switch (msg_type) {
        case NL_CMD_ADD_RULE:
            // die empfangene regel
            struct firewall_rule_format *received_rule;

            // die empfangene regel wird mit den empfangenen datengefuellt
            received_rule = (firewall_rule_format *)nlmsg_data(nlh);

            int ret = firewall_add_rule(received_rule);
            break;

        case NL_CMD_DELETE_RULE:
            break;

        case NL_CMD_CLEAR_RULES:
            break;

        default:
            printk(KERN_WARNING "Firewall: Unbekannter Befehlstyp %d von PID %d.\n", msg_type, pid);
            break;
    }
}

static int firewall_add_rule(struct firewall_rule_format *received_rule) {
    // neu allocalierte struktur
    struct rule_node *new_node = kmalloc(sizeof(rule_node), GFP_KERNEL);

    if (!new_node) {
        printk(KERN_ERR "Firewall: Speicherallokierungsfehler beim Hinzufügen einer Regel.\n");
        return -ENOMEM;
    }

    // hier wird die in die neu erstellte regel die empfangene regel rienkopiert
    memcpy(&new_node->rule, received_rule, sizeof(firewall_rule_format));

    // Schütze die Liste mit einem Mutex, bevor du sie änderst
    mutex_lock(&firewall_rules_mutex);
    list_add_tail(&new_node->list, &firewall_rules_list);
    mutex_unlock(&firewall_rules_mutex);

    printk(KERN_INFO "Firewall: Regel mit ID %u erfolgreich hinzugefügt.\n", new_node->rule.id);
    return 0; // Erfolg


}

module_init(init_firewall);
module_exit(exit_firewall);