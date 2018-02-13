[
    {
         "match": {
             "ip_dst": "baba::1",
             "ip_src": "dead::beef",
             "proto": "TCP",
             "sport": 42,
             "dport": 80,
             "transport_flags": 0
          },

          "srh" : {
             "segments": ["fc00::1", "fc00::2", "fc00::3"],
             "tlvs" : [ {"type":3, "value":"00000000000000000000000000000000002a", "length":18}, {"type":4, "length":2,"value":"0000"} ]
          }
    },
    {
         "match": {
             "ip_dst": "baba::1",
             "ip_src": "dead::beef",
             "proto": "UDP"
          },

          "srh" : {
             "segments": ["fc00::1337", "fc00::42"]
          }
    }
]

