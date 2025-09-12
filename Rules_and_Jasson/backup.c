#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <jansson.h>
#include <limits.h> 
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/time.h>


#define MY_FIREWALL_NETLINK_PROTOCOL 31


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
    struct rule_node *next;
} rule_node;

// diese befehle sagen den kernel ws er mit dem gesendeten anstellen soll
enum {
    NL_CMD_ADD_RULE = 1,    // Eine Regel hinzufügen
    NL_CMD_DELETE_RULE,     // Eine Regel löschen (nach ID)
    NL_CMD_CLEAR_RULES,     // Alle Regeln löschen
    // Füge weitere Befehle hinzu, wenn du sie brauchst (z.B. GET_RULES, STATUS_REPORT)
};

// Zustände für die Kommunikation
typedef enum {
    RESULT_NONE,
    RESULT_RECEIVED,
    RESULT_TIMEOUT
} thread_completion;

// struktur zum kommunizieren der threads in der sende funktion
typedef struct {
    pthread_mutex_t mutex;
    thread_completion status;
} thread_result;

// struktur zur ueebrgabe der argumente die die timer funktion braucht
typedef struct {
    thread_result *result;
    pthread_t receiver_thread_id;
} timer_args;

// struktur zur ueebrgabe der argumente die die recv funktion braucht
typedef struct {
    thread_result *result;
    pthread_t timer_thread_tid;
    int nl_sock;
} recv_args;

// verschiedene arten von ack packet antworten
enum {
    NL_CMD_ACK = 10,
    NL_CMD_ERROR = 11
};

void add_rule_to_list(struct firewall_rule_format *rule_data, struct rule_node **head_from_list) {
    //reserviert zufaelligen speicher fuer eine strctur rule_node_format
    struct rule_node *new_node = (rule_node *)malloc(sizeof(rule_node));

    if (!new_node) {
        fprintf(stderr, "Fehler: Speicherallokation für Regel-Knoten fehlgeschlagen.\n");
        exit(EXIT_FAILURE);
    }

    new_node->rule = *rule_data;
    new_node->next = NULL;

    if (*head_from_list == NULL) {
        *head_from_list = new_node;
    } else {
        struct rule_node *current = *head_from_list;
        while (current->next != NULL) {
            current = current->next;
        }

        current->next = new_node;
    }

}

int delete_rule_from_list_global(uint32_t id_to_delete, struct rule_node **head_from_list) {
    struct rule_node *current = *head_from_list;
    struct rule_node *prev = NULL; // Verfolger-Pointer

    // Fall: Liste ist leer
    if (*head_from_list == NULL) {
        printf("Liste ist leer, kann Regel ID %u nicht finden.\n", id_to_delete);
        return -1; // Regel nicht gefunden
    }

    // Fall: Das erste Element ist die zu löschende Regel
    if (current->rule.id == id_to_delete) {
        *head_from_list = current->next; // Kopf auf das nächste Element setzen
        free(current);        // Altes Kopfelement freigeben
        printf("Regel ID %u (Kopf) erfolgreich gelöscht.\n", id_to_delete);
        return 0; // Erfolg
    }

    // Fall: Die zu löschende Regel ist in der Mitte oder am Ende
    while (current != NULL && current->rule.id != id_to_delete) {
        prev = current;
        current = current->next;
    }

    // Wenn current NULL ist, wurde die Regel nicht gefunden
    if (current == NULL) {
        printf("Regel ID %u nicht in der Liste gefunden.\n", id_to_delete);
        return -1; // Regel nicht gefunden
    }

    // Wenn die Regel gefunden wurde (current != NULL):
    // prev zeigt auf das Element vor dem zu löschenden Element
    // current zeigt auf das zu löschende Element
    prev->next = current->next; // prev überspringt current
    free(current);              // current freigeben
    printf("Regel ID %u erfolgreich gelöscht.\n", id_to_delete);
    return 0; // Erfolg
}

void clear_list( struct rule_node **head_from_list) {
    if (*head_from_list == NULL) {
        return;
    }

    struct rule_node *current = *head_from_list;
    struct rule_node *nextElement = NULL;

    while(current->next != NULL) {
        nextElement = current->next;
        free(current);
        current = nextElement;
    }

    *head_from_list = NULL;
    printf("Liste erfolgreich geleert.\n");
}

// Funktion von umwandeln der Netzwerkpeotokolle von Strings in Enums
fw_protocol_t change_strings_from_networkprotocols_into_enums(const char *proto_str) {

    //uerberpruefen ob proto_str null ist
    if (!proto_str) return FW_PROTO_UNKNOWN;

    // 2. String-Vergleiche:
    // Die Funktion verwendet 'strcmp()' (string compare) aus <string.h>,
    // um den Eingabestring mit bekannten Protokollnamen zu vergleichen.
    // 'strcmp()' gibt 0 zurück, wenn die Strings identisch sind.
    if (strcmp(proto_str, "TCP") == 0) return FW_PROTO_TCP;
    if (strcmp(proto_str, "UDP") == 0) return FW_PROTO_UDP;
    if (strcmp(proto_str, "ICMP") == 0) return FW_PROTO_ICMP;
    if (strcmp(proto_str, "ANY") == 0) return FW_PROTO_ANY;

    //prinausgabe falls es kein treffendes protocoll gibt 
    fprintf(stderr, "Unbekanntes Protokoll: %s\n", proto_str);

    // Anschließend wird FW_PROTO_UNKNOWN zurückgegeben, um anzuzeigen, dass das Protokoll nicht erkannt wurde.
    return FW_PROTO_UNKNOWN;
}

// Funktion von umwandeln der Aktionstypen von Strings in Enums
fw_action_t change_strings_from_actiontypes_into_enums(const char *action_str) {

    //uerberpruefen ob action_str null ist
    if (!action_str) return FW_ACTION_UNKWON;

    // 2. String-Vergleiche:
    // Vergleicht den Eingabestring mit den bekannten Aktionsnamen.
    if (strcmp(action_str, "ACCEPT") == 0) return FW_ACTION_ACCEPT;
    if (strcmp(action_str, "DROP") == 0) return FW_ACTION_DROP;
    if (strcmp(action_str, "REJECT") == 0) return FW_ACTION_REJECT;
    
    
    // gibt FW_ACTION_UNKNOWN zurück.
    fprintf(stderr, "Unbekannte Aktion: %s\n", action_str);
    return FW_ACTION_UNKWON;
}

// Funktion zum umwandeln der IP Strings in ein 32-Bit-Integer

//const char *ip_cidr_str: Das ist der Eingabestring, der die IP-Adresse und optional die CIDR-Präfixlänge enthält
//(z.B. "192.168.1.0/24", "10.0.0.5", "ANY"). const bedeutet, dass der String innerhalb der Funktion nicht verändert wird

//uint32_t *ip: Ein Ausgabe-Pointer. Die geparste IP-Adresse wird als 32-Bit-Integer an dieser Speicheradresse gespeichert.

//uint32_t *mask: Ein weiterer Ausgabe-Pointer. Die berechnete Subnetzmaske wird als 32-Bit-Integer an dieser Speicheradresse gespeichert.
int change_IpString_into_32BitInteger(const char *ip_cidr_str, uint32_t *ip, uint32_t *mask) {
    // ueberprueft das alle pointer guektig sind
    if (!ip_cidr_str || !ip || !mask) return -1;

    //
    char *str_copy = strdup(ip_cidr_str);
    if (!str_copy) {
        perror("strdup failed"); // Fehler bei der Speicherallokation
        return -1;
    }

    // Wenn der String "ANY" ist, bedeutet das, dass keine spezifische IP-Adresse oder Maske
    // angewendet werden soll. In diesem Fall werden IP und Maske auf 0 (0.0.0.0) gesetzt.
    if (strcmp(ip_cidr_str, "ANY") == 0) {
        *ip = 0;       // Repräsentiert 0.0.0.0
        *mask = 0;     // Repräsentiert 0.0.0.0
        free(str_copy); // Speicher der Kopie freigeben
        return 0;      // Erfolg
    }


    char *token;
    char *rest = str_copy; // Pointer für strtok_r

    // Prüfen auf "ANY"
    if (strcmp(ip_cidr_str, "ANY") == 0) {
        *ip = 0;       // 0.0.0.0
        *mask = 0;     // 0.0.0.0
        free(str_copy);
        return 0;
    }

    // IP-Adresse extrahieren
    token = strtok_r(rest, "/", &rest);
    if (!token) {
        fprintf(stderr, "Fehler: Ungültiges IP/CIDR-Format: %s\n", ip_cidr_str);
        free(str_copy);
        return -1;
    }

    struct in_addr sa; // Struktur für inet_pton
    if (inet_pton(AF_INET, token, &(sa.s_addr)) != 1) {
        fprintf(stderr, "Fehler: Ungültige IP-Adresse: %s\n", token);
        free(str_copy);
        return -1;
    }
    *ip = ntohl(sa.s_addr); // Konvertiere von Network Byte Order zu Host Byte Order

    // CIDR-Präfixlänge extrahieren (falls vorhanden)
    int prefix_len = 32; // Standard: /32 (einzelne IP)
    if (rest && *rest != '\0') {
        prefix_len = atoi(rest);
        if (prefix_len < 0 || prefix_len > 32) {
            fprintf(stderr, "Fehler: Ungültige CIDR-Präfixlänge: %s\n", rest);
            free(str_copy);
            return -1;
        }
    }

    // Maske generieren (in Host Byte Order)
    if (prefix_len == 0) {
        *mask = 0; // 0.0.0.0
    } else {
        *mask = 0xFFFFFFFF << (32 - prefix_len); // z.B. 24 -> 0xFFFFFF00
    }

    free(str_copy);
    return 0;
}

//chnage port string into bytes
int parse_port_range_string_and_change_into_bytes(const char *port_str, fw_port_range_t *range) {
    if (!port_str || !range) return -1;

    // Prüfen auf "ANY"
    if (strcmp(port_str, "ANY") == 0) {
        range->start = 0;
        range->end = 65535; // Max. Portnummer
        return 0;
    }

    char *str_copy = strdup(port_str);
    if (!str_copy) {
        fprintf(stderr, "Fehler: strdup für Port-String fehlgeschlagen.\n");
        return -1;
    }

    char *dash = strchr(str_copy, '-');
    if (dash) {
        // Portbereich erkannt
        *dash = '\0'; // Ersten Teil nullterminieren
        range->start = (uint16_t)atoi(str_copy);
        range->end = (uint16_t)atoi(dash + 1);
    } else {
        // Einzelner Port
        range->start = (uint16_t)atoi(str_copy);
        range->end = range->start;
    }

    free(str_copy);

    if (range->start > 65535 || range->end > 65535 || range->start > range->end) {
        fprintf(stderr, "Fehler: Ungültiger Port- oder Portbereich: %s\n", port_str);
        return -1;
    }
    return 0;
}

// alle moeglichen fehler die beim parsen passieren koennen
#define PARSE_SUCCESS           0
#define ERROR_INVALID_ID        -1
#define ERROR_INVALID_NAME      -2
#define ERROR_INVALID_ENABLED   -3
#define ERROR_INVALID_PRIORITY  -4
#define ERROR_INVALID_PROTOCOL  -5
#define ERROR_INVALID_SRC_IP    -6
#define ERROR_INVALID_DST_IP    -7
#define ERROR_INVALID_SRC_PORT  -8
#define ERROR_INVALID_DST_PORT  -9
#define ERROR_INVALID_ACTION    -10

// Fehlerfunktion wenn etwas beim Parsen schief geht
void error_function(struct firewall_rule_format *new_rule, struct rule_node **head_from_list, int i) {
    // Füge die Regel (auch wenn fehlerhaft) zur Liste hinzu, um alle Parsingergebnisse zu verfolgen.
        if (new_rule->result_code != PARSE_SUCCESS) {
            add_rule_to_list(new_rule, head_from_list);
            printf("Regel %zu (ID: %u) wurde mit Fehlern geparst erfolgreich hinzugefügt.\n", i, new_rule->id);

            // hier wird der genaue Fehelr identifiziert
            switch (new_rule->result_code) {
            case ERROR_INVALID_ID:
                fprintf(stderr, "Ungültige oder fehlende ID.\n");
                break;
            case ERROR_INVALID_NAME:
                fprintf(stderr, "Ungültiger oder fehlender Name.\n");
                break;
            case ERROR_INVALID_ENABLED:
                fprintf(stderr, "Ungültiger oder fehlender 'enabled'-Status.\n");
                break;
            case ERROR_INVALID_PRIORITY:
                fprintf(stderr, "Ungültige oder fehlende Priorität.\n");
                break;
            case ERROR_INVALID_PROTOCOL:
                fprintf(stderr, "Ungültiges oder unbekanntes Protokoll.\n");
                break;
            case ERROR_INVALID_SRC_IP:
                fprintf(stderr, "Ungültige Quell-IP-Adresse.\n");
                break;
            case ERROR_INVALID_DST_IP:
                fprintf(stderr, "Ungültige Ziel-IP-Adresse.\n");
                break;
            case ERROR_INVALID_SRC_PORT:
                fprintf(stderr, "Ungültiger Quell-Port oder Portbereich.\n");
                break;
            case ERROR_INVALID_DST_PORT:
                fprintf(stderr, "Ungültiger Ziel-Port oder Portbereich.\n");
                break;
            case ERROR_INVALID_ACTION:
                fprintf(stderr, "Ungültige oder unbekannte Aktion.\n");
                break;
            default:
                fprintf(stderr, "Unbekannter Parsing-Fehler (Code: %d).\n", new_rule->result_code);
                break;
            }

        } else {
            fprintf(stderr, "Regel %zu (ID: %u, wenn verfügbar) konnte nicht geparst werden und konnte nicht zur liste hinzugefuegt werden\n", i, new_rule->id);
        }
}


// funktion zum parsen der regeln
int parse_rules_json_file(const char *filename, struct rule_node **head_from_list) {
    json_error_t error;
    json_t *root;

    // 1. JSON-Datei laden
    root = json_load_file(filename, 0, &error);
    if (!root) {
        fprintf(stderr, "Fehler beim Laden der JSON-Datei '%s': %s (Zeile %d, Spalte %d)\n",
                filename, error.text, error.line, error.column);
        return NULL; // NULL bei Dateifehler zurückgeben
    }


    // 2. Überprüfen, ob das Root-Element ein Array ist
    if (!json_is_array(root)) {
        fprintf(stderr, "Fehler: Das Root-Element der JSON-Datei ist kein Array.\n");
        json_decref(root); // JSON-Objekt freigeben
        return NULL; // NULL zurückgeben, wenn es kein Array ist
    }

    // Anzahl der Regeln im Array ermitteln
    size_t num_json_elements = json_array_size(root);
    printf("Starte das Parsen von %zu Regeln aus '%s'.\n", num_json_elements, filename);

    for(size_t i = 0; i < num_json_elements; i++) {
        // i ist die aktuelle regel
        json_t *value_json_obj = json_array_get(root, i); // Holen Sie das JSON-Objekt für die aktuelle Regel

        

        // structur in die die regel geschrieben wird
        struct firewall_rule_format new_rule;

        // Prüfen, ob das Element ein JSON-Objekt ist (falls nicht, überspringen)
        if (!json_is_object(value_json_obj)) {
            fprintf(stderr, "Warnung: Element am Index %zu ist kein JSON-Objekt. Wird übersprungen.\n", i);
            continue; // Nächstes Element verarbeiten
        }

        // parsen der id       
        json_t *id_json = json_object_get(value_json_obj, "id");
        if (json_is_integer(id_json)) {
            new_rule.id = json_integer_value(id_json);
        } else {
            fprintf(stderr, "Fehler bei Regel %zu: 'id' fehlt oder ist kein Integer. Regel wird als fehlerhaft markiert.\n", i);
            new_rule.result_code = ERROR_INVALID_ID;
            error_function(&new_rule, head_from_list, i); // Springe zum Fehler-Handler für diese einzelne Regel
            continue;
        }

        // parsen des namen
        json_t *name_json = json_object_get(value_json_obj, "name");
        if (json_is_string(name_json)) {
            strncpy(new_rule.name, json_string_value(name_json), sizeof(new_rule.name) - 1);
            new_rule.name[sizeof(new_rule.name) - 1] = '\0'; // Null-Terminierung sichern
        } else {
            fprintf(stderr, "Fehler bei Regel %zu: 'name' fehlt oder ist kein String. Regel wird als fehlerhaft markiert.\n", i);
            new_rule.result_code = ERROR_INVALID_NAME;
            error_function(&new_rule, head_from_list, i);
            continue;
        }

        // parsen ob die regel aktiev ist
        json_t *enabled_json = json_object_get(value_json_obj, "enabled");
        if (json_is_boolean(enabled_json)) {
            new_rule.enabled = json_boolean_value(enabled_json);
        } else {
            fprintf(stderr, "Fehler bei Regel %zu: 'enabled' fehlt oder ist kein Boolean. Regel wird als fehlerhaft markiert.\n", i);
            new_rule.result_code = ERROR_INVALID_ENABLED;
            error_function(&new_rule, head_from_list, i);
            continue;
        }

        // parsen der prioritaet
        json_t *priority_json = json_object_get(value_json_obj, "priority");
        if (json_is_integer(priority_json)) {
            new_rule.priotity = json_integer_value(priority_json);
        } else {
            fprintf(stderr, "Fehler bei Regel %zu: 'priority' fehlt oder ist kein Integer. Regel wird als fehlerhaft markiert.\n", i);
            new_rule.result_code = ERROR_INVALID_PRIORITY;
            error_function(&new_rule, head_from_list, i);
            continue;
        }

        // parsen des protocoll typens
        json_t *protocol_json = json_object_get(value_json_obj, "protocol");
        if (json_is_string(protocol_json)) {
            new_rule.protocoll = change_strings_from_networkprotocols_into_enums(json_string_value(protocol_json));
            if (new_rule.protocoll == FW_PROTO_UNKNOWN) {
                fprintf(stderr, "Fehler bei Regel %zu: Unbekanntes Protokoll '%s'. Regel wird als fehlerhaft markiert.\n", i, json_string_value(protocol_json));
                error_function(&new_rule, head_from_list, i);
            }
        } else {
            fprintf(stderr, "Fehler bei Regel %zu: 'protocol' fehlt oder ist kein String. Regel wird als fehlerhaft markiert.\n", i);
            new_rule.result_code = ERROR_INVALID_PROTOCOL;
            error_function(&new_rule, head_from_list, i);
            continue;
        }

        // parsen der source_ip
        json_t *src_ip_json = json_object_get(value_json_obj, "source_ip");
        if (json_is_string(src_ip_json)) {
            if (change_IpString_into_32BitInteger(json_string_value(src_ip_json), &new_rule.src_ip, &new_rule.src_mask) != 0) {
                fprintf(stderr, "Fehler bei Regel %zu: Ungültige 'source_ip'. Regel wird als fehlerhaft markiert.\n", i);
                error_function(&new_rule, head_from_list, i);
            }
        } else {
            fprintf(stderr, "Fehler bei Regel %zu: 'source_ip' fehlt oder ist kein String. Regel wird als fehlerhaft markiert.\n", i);
            new_rule.result_code = ERROR_INVALID_SRC_IP;
            error_function(&new_rule, head_from_list, i);
            continue;
        }

        // parsen der destination_ip
        json_t *dst_ip_json = json_object_get(value_json_obj, "destination_ip");
        if (json_is_string(dst_ip_json)) {
            if (change_IpString_into_32BitInteger(json_string_value(dst_ip_json), &new_rule.dst_ip, &new_rule.dst_mask) != 0) {
                fprintf(stderr, "Fehler bei Regel %zu: Ungültige 'destination_ip'. Regel wird als fehlerhaft markiert.\n", i);
                error_function(&new_rule, head_from_list, i);
            }
        } else {
            fprintf(stderr, "Fehler bei Regel %zu: 'destination_ip' fehlt oder ist kein String. Regel wird als fehlerhaft markiert.\n", i);
            new_rule.result_code = ERROR_INVALID_DST_IP;
            error_function(&new_rule, head_from_list, i);
            continue;
        }

        //parsen des sources portes
        json_t *src_port_json = json_object_get(value_json_obj, "source_port");
        if (json_is_string(src_port_json)) {
            if (parse_port_range_string_and_change_into_bytes(json_string_value(src_port_json), &new_rule.src_port) != 0) {
                fprintf(stderr, "Fehler bei Regel %zu: Ungültige 'source_port'. Regel wird als fehlerhaft markiert.\n", i);
                error_function(&new_rule, head_from_list, i);
            }
        } else {
            fprintf(stderr, "Fehler bei Regel %zu: 'source_port' fehlt oder ist kein String. Regel wird als fehlerhaft markiert.\n", i);
            new_rule.result_code = ERROR_INVALID_SRC_PORT;
            error_function(&new_rule, head_from_list, i);
        }

        // parsen des destination_ports
        json_t *dst_port_json = json_object_get(value_json_obj, "destination_port");
        if (json_is_string(dst_port_json)) {
            if (parse_port_range_string_and_change_into_bytes(json_string_value(dst_port_json), &new_rule.dst_port) != 0) {
                fprintf(stderr, "Fehler bei Regel %zu: Ungültige 'destination_port'. Regel wird als fehlerhaft markiert.\n", i);
                error_function(&new_rule, *head_from_list, i);
            }
        } else {
            fprintf(stderr, "Fehler bei Regel %zu: 'destination_port' fehlt oder ist kein String. Regel wird als fehlerhaft markiert.\n", i);
            new_rule.result_code = ERROR_INVALID_DST_PORT;
            error_function(&new_rule, head_from_list, i);
            continue;
        }

        // parsen der action
        json_t *action_json = json_object_get(value_json_obj, "action");
        if (json_is_string(action_json)) {
            new_rule.action = change_strings_from_actiontypes_into_enums(json_string_value(action_json));
            if (new_rule.action == FW_ACTION_UNKWON) {
                fprintf(stderr, "Fehler bei Regel %zu: Unbekannte Aktion '%s'. Regel wird als fehlerhaft markiert.\n", i, json_string_value(action_json));
                error_function(&new_rule, head_from_list, i);
            }
        } else {
            fprintf(stderr, "Fehler bei Regel %zu: 'action' fehlt oder ist kein String. Regel wird als fehlerhaft markiert.\n", i);
            new_rule.result_code = ERROR_INVALID_ACTION;
            error_function(&new_rule, head_from_list, i);
            continue;
        }

        new_rule.result_code = PARSE_SUCCESS;

        // hier wird ueberprueft ob die regel aktiviert ist
        if (new_rule.enabled = false) {
            printf("Die Regel %zu ist nicht aktiviert und wurde somit auch nicth geladen\n", new_rule.name);
            continue;
        }

        add_rule_to_list(&new_rule, head_from_list);

        if(new_rule.result_code == PARSE_SUCCESS) {
            printf("Die Regel %zu wurde  hinzuegfuegt!\n", new_rule.name);
        }

          
    }

    json_decref(root); // JSON-Struktur freigeben, da wir die Daten nun in unserer Liste haben
    return 0; 



}

// Funktion zum Ausdrucken einer einzelnen Firewall-Regel
void print_rule(const firewall_rule_format *rule) {
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    char src_mask_str[INET_ADDRSTRLEN];
    char dst_mask_str[INET_ADDRSTRLEN];

    struct in_addr addr;
    addr.s_addr = 0; // Standardwert für Sicherheit

    const char *display_src_ip;
    const char *display_src_mask;
    const char *display_dst_ip;
    const char *display_dst_mask;

    // Quell-IP und Maske
    if (rule->result_code == ERROR_INVALID_SRC_IP) {
        display_src_ip = "INVALID";
        display_src_mask = "INVALID";
    } else if (rule->src_ip == 0 && rule->src_mask == 0) { // Dies könnte ANY sein
        display_src_ip = "ANY (0.0.0.0)";
        display_src_mask = "ANY (0.0.0.0)";
    } else {
        addr.s_addr = htonl(rule->src_ip);
        inet_ntop(AF_INET, &addr, src_ip_str, sizeof(src_ip_str));
        display_src_ip = src_ip_str;

        addr.s_addr = htonl(rule->src_mask);
        inet_ntop(AF_INET, &addr, src_mask_str, sizeof(src_mask_str));
        display_src_mask = src_mask_str;
    }

    // Ziel-IP und Maske
    if (rule->result_code == ERROR_INVALID_DST_IP) {
        display_dst_ip = "INVALID";
        display_dst_mask = "INVALID";
    } else if (rule->dst_ip == 0 && rule->dst_mask == 0) { // Dies könnte ANY sein
        display_dst_ip = "ANY (0.0.0.0)";
        display_dst_mask = "ANY (0.0.0.0)";
    } else {
        addr.s_addr = htonl(rule->dst_ip);
        inet_ntop(AF_INET, &addr, dst_ip_str, sizeof(dst_ip_str));
        display_dst_ip = dst_ip_str;

        addr.s_addr = htonl(rule->dst_mask);
        inet_ntop(AF_INET, &addr, dst_mask_str, sizeof(dst_mask_str));
        display_dst_mask = dst_mask_str;
    }

    printf("--- Regel ID: %u (%s) ---\n", rule->id, rule->name[0] != '\0' ? rule->name : "N/A");
    printf("  Enabled: %s\n", rule->enabled ? "True" : "False");
    printf("  Priority: %d\n", rule->priotity);

    // PROTOKOLL-AUSGABE KORRIGIERT
    const char* protocol_str;
    switch (rule->protocoll) {
        case FW_PROTO_TCP: protocol_str = "TCP"; break;
        case FW_PROTO_UDP: protocol_str = "UDP"; break;
        case FW_PROTO_ICMP: protocol_str = "ICMP"; break;
        case FW_PROTO_ANY: protocol_str = "ANY"; break;
        default: protocol_str = "UNKNOWN_PROTOCOL"; break; // Fallback für ungültigen Enum-Wert
    }
    printf("  Protocol: %s\n", protocol_str); // Jetzt korrekt einen String ausgeben

    printf("  Source IP: %s / Mask: %s\n", display_src_ip, display_src_mask);
    printf("  Destination IP: %s / Mask: %s\n", display_dst_ip, display_dst_mask);

    // Ports
    if (rule->result_code == ERROR_INVALID_SRC_PORT) {
        printf("  Source Port: INVALID\n");
    } else if (rule->src_port.start == 0 && rule->src_port.end == 65535) {
        printf("  Source Port: ANY\n");
    } else if (rule->src_port.start == rule->src_port.end) {
        printf("  Source Port: %hu\n", rule->src_port.start);
    } else {
        printf("  Source Port: %hu-%hu\n", rule->src_port.start, rule->src_port.end);
    }

    if (rule->result_code == ERROR_INVALID_DST_PORT) {
        printf("  Destination Port: INVALID\n");
    } else if (rule->dst_port.start == 0 && rule->dst_port.end == 65535) {
        printf("  Destination Port: ANY\n");
    } else if (rule->dst_port.start == rule->dst_port.end) {
        printf("  Destination Port: %hu\n", rule->dst_port.start);
    } else {
        printf("  Destination Port: %hu-%hu\n", rule->dst_port.start, rule->dst_port.end);
    }
    
    // AKTION-AUSGABE KORRIGIERT
    const char* action_str;
    switch (rule->action) {
        case FW_ACTION_ACCEPT: action_str = "ACCEPT"; break;
        case FW_ACTION_DROP: action_str = "DROP"; break;
        case FW_ACTION_REJECT: action_str = "REJECT"; break;
        default: action_str = "UNKNOWN_ACTION"; break; // Fallback für ungültigen Enum-Wert
    }
    printf("  Action: %s\n", action_str); // Jetzt korrekt einen String ausgeben

    // PARSING STATUS KORRIGIERT
    char status_buffer[64]; // Genug Platz für den String
    if (rule->result_code == PARSE_SUCCESS) {
        snprintf(status_buffer, sizeof(status_buffer), "OK");
    } else {
        snprintf(status_buffer, sizeof(status_buffer), "ERROR (Code: %d)", rule->result_code);
    }
    printf("  Parsing Status: %s\n", status_buffer);
    printf("---------------------------\n\n");
} 

void  *timer(void *arg) {
    // Caste das void*-Argument in einen Zeiger auf die Parameter-Struktur
    timer_args *args = (timer_args *)arg;
    
    // Greife auf die einzelnen Parameter über den Zeiger zu
    thread_result *result = args->result;
    pthread_t receiver_tid = args->receiver_thread_id;

    // Definiere die Timeout-Zeit in Sekunden
    const int timeout_seconds = 10;

    struct timeval start_time, current_time;
    long elapsed_seconds;

    // aktuelle zeit
    gettimeofday(&start_time, NULL);

    // Die Schleife wartet bis das Timeout erreicht ist
    do {
        gettimeofday(&current_time, NULL);
        elapsed_seconds = current_time.tv_sec - start_time.tv_sec;
        usleep(100000); 
    } while (elapsed_seconds < timeout_seconds);

    // Prüfen, ob das Ergebnis noch nicht gesetzt wurde
    if (result->status == RESULT_NONE) {
        // Der Timer hat als Erster geendet, daher setzen wir den Status auf Timeout
        result->status = RESULT_TIMEOUT;
        printf("Timer-Thread: Timeout erreicht. Breche Receiver ab.\n");
        // Breche den Receiver-Thread ab, da er blockiert
        pthread_cancel(receiver_tid);
    }

    return NULL;
}

void *recv_msg(void *arg) {
    // Caste das void*-Argument in einen Zeiger auf die Parameter-Struktur
    recv_args *args = (recv_args *)arg;
    
    // Greife auf die einzelnen Parameter über den Zeiger zu
    thread_result *result = args->result;
    pthread_t timer_tid = args->timer_thread_tid;
    int nl_sock = args->nl_sock;

    // hier wird das empfange packet 
    char buffer[4096];
    // struktur enhaelt alle informationen fuer den empfang
    struct msghdr msg;
    // beschreibt den buffer
    struct iovec iov;


    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // hier wird auf das packet gewartet
    ssize_t ret = recvmsg(nl_sock, &msg, 0);

    if (ret > 0) {
        // gibt zu griff auf den header
        struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
        // gibt zugriff auf den payload
        void *payload = NLMSG_DATA(nlh);

        if (result->status == RESULT_NONE) {
            // hier wird geguckt ob die empfangenen daten unbeshcaedigt sind
            if (nlh->nlmsg_type == NL_CMD_ACK) {
                result->status = RESULT_RECEIVED;
                printf("Das Ack-Packet wurde erfolgreich empfangen"\n);
            } else if (nlh->nlmsg_type == NL_CMD_ERROR) {
                result->status = RESULT_RECEIVED;
                printf("Es gab einen Fehler beim Empfangen des Pakcets\n");
            }
        }

        
    }

    pthread_cancel(&timer_tid);

    return NULL;



    
}

// int nl_sock_fd ist der bereitserstellet socket
int send_rules_to_kernel(struct rule_node **head, int nl_sock_fd, int command) {
    struct rule_node *current_rule = *head;

    ssize_t ret;
    struct nlmsghdr *nlh = NULL;

    int num_send_trys = 3;

    // ides fuer die beiden threads
    pthread_t timer_thread;
    pthread_t recv_msg_thread;

    // struktur  zur kommunikation der threads
    thread_result result_data_thread;

    // struktur fuer die timer argumente
    timer_args timer_args;
    timer_args.result = &result_data_thread;
    timer_args.receiver_tid = recv_msg_thread;

    // struktur fuer die timer argumente
    recv_args recv_args;
    recv_args.result = &result_data_thread;
    recv_args.timer_tid = timer_thread;

    while(current_rule != NULL) {

        struct sockaddr_nl dest_addr; //Zieladresse
        struct iovec iov;            // Für sendmsg/recvmsg
        struct msghdr msg;           // Für sendmsg/recvmsg

        // 1. Berechnung der Nachrichtengröße
        // NLMSG_SPACE(payload_len) berechnet den Platz für den Netlink-Header + die Payload
        size_t msg_len = NLMSG_SPACE(sizeof(current_rule->rule));

        // 2. Speicher für die Netlink-Nachricht allozieren und initialisieren
        nlh = (struct nlmsghdr *)malloc(msg_len);
        if (!nlh) {
            perror("malloc nlh");
            return -1;
        }
        memset(nlh, 0, msg_len); // Speicher auf Null setzen


        // 3. Netlink-Nachrichtenheader füllen
        nlh->nlmsg_len = msg_len;
        nlh->nlmsg_type = command; // Dein benutzerdefinierter Befehl
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK; // Dies ist eine Anfrage, und wir wollen eine Bestätigung
        nlh->nlmsg_seq = 0; // Sequenznummer (einfachheitshalber 0, kann für komplexere Kommunikation genutzt werden)
        nlh->nlmsg_pid = getpid(); // PID des sendenden Userspace-Prozesses

        // hier wird eine kopie von current_rule erstellt, weil der die ports in bytes umgewandelt werden muessen
        // was das original veraendern wuerde
        rule_node converted_rule = *current_rule;

        // Konvertiere IP-Adressen und Masken von Host Byte Order zu Network Byte Order
        converted_rule.rule.src_ip = htonl(current_rule->rule.src_ip);
        converted_rule.rule.src_mask = htonl(current_rule->rule.src_mask);
        converted_rule.rule.dst_ip = htonl(current_rule->rule.dst_ip);
        converted_rule.rule.dst_mask = htonl(current_rule->rule.dst_mask);

        // Konvertiere Portnummern von Host Byte Order zu Network Byte Order
        // BEACHTE: uint16_t wird von htons erwartet und zurückgegeben.
        converted_rule.rule.src_port.start = htons(current_rule->rule.src_port.start);
        converted_rule.rule.src_port.end = htons(current_rule->rule.src_port.end);
        converted_rule.rule.dst_port.start = htons(current_rule->rule.dst_port.start);
        converted_rule.rule.dst_port.end = htons(current_rule->rule.dst_port.end);

        // Kopiere die konvertierte Regel in den Datenbereich der Netlink-Nachricht
        memcpy(NLMSG_DATA(nlh), &converted_rule, sizeof(rule_node));

        // 5. Zieladresse für die Netlink-Nachricht festlegen (der Kernel)
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.nl_family = AF_NETLINK;
        dest_addr.nl_pid = 0; // PID 0 ist immer der Kernel
        dest_addr.nl_groups = 0; // Keine Multicast-Gruppen für unicast-Kommunikation

        // 6. iovec-Struktur für sendmsg füllen
        memset(&iov, 0, sizeof(iov));
        iov.iov_base = (void *)nlh; // Zeiger auf den Nachrichtenpuffer
        iov.iov_len = nlh->nlmsg_len; // Länge der Nachricht

        // 7. msghdr-Struktur für sendmsg füllen
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = (void *)&dest_addr; // Zieladresse
        msg.msg_namelen = sizeof(dest_addr);
        msg.msg_iov = &iov; // iovec-Array
        msg.msg_iovlen = 1; // Anzahl der iovec-Elemente

        for(int i = 1; i < num_send_trys; i++) {
            // Nachricht senden
            ret = sendmsg(nl_sock_fd, &msg, 0);
            if (ret < 0) {
                printf("Es gab einen Fehler beim Senden der Nachricht %d\n", current_rule->rule.id);
                free(nlh);
                continue;
            } else {
                printf("Die Nachricht mit der Id %d wurde gesendet!\n", current_rule->rule.id);
            }  

            // starten des recv threads
            if (pthread_create(&recv_msg_thread, NULL, recv_msg, &recv_args) != 0) {
                perror("Fehler beim Starten vom Recv-Thread");
                continue;
            }

            // starten des timer threads
            if (pthread_create(&timer_thread, NULL, timer, &timer_args) != 0) {
                perror("Fehler beim Starten von Timer-Thread");
                continue;
            }

            // Warte auf die Beendigung beider Threads
            pthread_join(timer_thread, NULL);
            pthread_join(recv_msg_thread, NULL);

            // auslesen der status struktur
            if (result_data_thread.status == RESULT_RECEIVED) {
                printf(" Ergebnis: Eine ACK-Nachricht wurde erfolgreich empfangen.\n");
                break;
            } else if (result_data_thread.status == RESULT_TIMEOUT) {
                printf(" Ergebnis: Timeout! Keine Nachricht wurde empfangen.\n");
                continue;
            } else {
                // Dies sollte nicht passieren, da einer der beiden Threads das Ergebnis setzen sollte
                printf(" Ergebnis: Unbekannter Status.\n");
            }
                        

        }

        if (i == num_send_trys) {
            printf("Es wurde Ergebnis los probiert die Regeln an den Kernel zu senden.\n");
        }
        

        free(nlh); // Allozierten Speicher freigeben


        current_rule = current_rule->next;
    }

}


int main(int argc, char *argv[]) {
   //zeigt auf das erste eleemnt der linked list
    struct rule_node *head;

    // 1. Prüfe, ob der Dateiname als Kommandozeilenargument übergeben wurde
    if (argc != 2) { // argc ist die Anzahl der Argumente, argv[0] ist der Programmname, argv[1] der erste Parameter
        fprintf(stderr, "Verwendung: %s <json_datei>\n", argv[0]);
        fprintf(stderr, "Beispiel: %s rules.json\n", argv[0]);
        return EXIT_FAILURE; // Programm mit Fehler beenden
    }

    // 2. Den Dateinamen aus den Kommandozeilenargumenten holen
    const char *json_filename = argv[1]; 

    // hier werden die regeln geparst und die linked list erstellt
    if (parse_rules_json_file(json_filename, &head) == 0 ) {
        printf("Das parsen wurde erfolgreich abgeschlossen\n");
    }

    struct rule_node *current = head;

    while (current != NULL) {
        print_rule(&current->rule);
        current = current->next;
    }

    // Netlink-Socket erstellen und binden
    int nl_sock_fd = socket(AF_NETLINK, SOCK_RAW, MY_FIREWALL_NETLINK_PROTOCOL);
    if (nl_sock_fd < 0) {
        perror("Fehler beim Erstellen des Netlink-Sockets");
        return EXIT_FAILURE;
    }

    struct sockaddr_nl src_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); // Binde an die eigene Prozess-ID
    src_addr.nl_groups = 0;     // Keine Multicast-Gruppen

    if (bind(nl_sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        perror("Fehler beim Binden des Netlink-Sockets");
        close(nl_sock_fd);
        return EXIT_FAILURE;
    }
    printf("Netlink-Socket erfolgreich erstellt und gebunden (PID: %d).\n", getpid());

    send_rules_to_kernel(&head, nl_sock_fd, NL_CMD_ADD_RULE);


    clear_list(&head);
    
    
}






