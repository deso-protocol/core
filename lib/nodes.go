package lib

// @StarGeezer - 23 Dec 2024
//
// Description: improved structure to make '/get-app-state' more useful for live services.
// May also provide trusted active node list for backend init.
// Updated with active statuses and known changes to URLs and service availability.
//
// ** Note: existing keys retained to avoid breaking changes **
//
// New keys to specify: 
// - whether entry is active (for history and active service lookups)
// - URL endpoints for service(s) provided:- (presence/absence indicates service provision)
//     - URL (backend)
//     - FrontendURL (frontend)
//     - GraphqlURL (graphQL)
// - Entry/OwnerPublicKeyBase58Check (consistency over username, provide profile & avatar for listings)

type DeSoNode struct {
    	// Whether entry is active
	Active bool

	// Name of the node, displayed to users
	Name string

    	// DeSo username of the node owner
	Owner string

	// HTTPs URL to backend/node (IF operating backend/node API service)
	URL *string

    	// HTTPs URL to frontend (IF operating frontend service)
    	FrontendURL *string

    	// HTTPs URL to graphql (IF operating graphql service)
    	GraphqlURL *string

    	// PublicKeyBase58Check for the entry
	EntryPublicKeyBase58Check string

    	// PublicKeyBase58Check for the owner of this entry
	OwnerPublicKeyBase58Check string
}

//
// This list of nodes is maintained by the core DeSo developer team.
//
// If you run a DeSo node that has been online for at least one month you may submit a pull request to add your
// node to the list of nodes.
//
// When submitting a post, add the following to PostExtraData:
//   "Node": "ID"
//
// If your node is in the list then other nodes will be able to know where users are posting and can include
// a link to your node and give you free advertising.
//

var NODES = map[uint64]DeSoNode{
    1: {
        Active: true,
        Name: "DeSo",
        Owner: "nader",
        URL: "https://node.deso.org",
        FrontendURL: "https://node.deso.org",
        GraphqlURL: "https://graphql-prod.deso.com",
        EntryPublicKeyBase58Check: "BC1YLgk64us61PUyJ7iTEkV4y2GqpHSi8ejWJRnZwsX6XRTZSfUKsop",
        OwnerPublicKeyBase58Check: "BC1YLhyuDGeWVgHmh3UQEoKstda525T1LnonYWURBdpgWbFBfRuntP5",
    },
    2: {
        Active: true,
        Name: "BitClout",
        Owner: "nader",
        URL: "https://bitclout.com",
        FrontendURL: "https://bitclout.com",
        EntryPublicKeyBase58Check: "BC1YLgk64us61PUyJ7iTEkV4y2GqpHSi8ejWJRnZwsX6XRTZSfUKsop",
        OwnerPublicKeyBase58Check: "BC1YLhyuDGeWVgHmh3UQEoKstda525T1LnonYWURBdpgWbFBfRuntP5",
    },
    3: {
        Active: true,
        Name: "Diamond",
        Owner: "Zordon",
        URL: "https://diamondapp.com",
        FrontendURL: "https://diamondapp.com",
        EntryPublicKeyBase58Check: "BC1YLgTKfwSeHuNWtuqQmwduJM2QZ7ZQ9C7HFuLpyXuunUN7zTEr5WL",
        OwnerPublicKeyBase58Check: "BC1YLiUro1G14Zqv5bmB62ZfF9fJEdcidbCDvW1r8iNDdp5qikuNDoe",
    },
    4: {
        Active: false,
        Name: "Desofy",
        Owner: "Ribal",
        FrontendURL: "https://desofy.app",
        EntryPublicKeyBase58Check: "BC1YLh5pKXs8NqaUtN8Gzi3rfoAgG2VWio2NER7baDkG8T2x7wRnSwa",
        OwnerPublicKeyBase58Check: "BC1YLgPCJ6tgmRQNvYLM2i48U6B1rWM3PuWPKHivpws6TS627ZL4TVn",
    },
    5: {
        Active: false,
        Name: "Flick",
        Owner: "nigeleccles",
        FrontendURL: "https://flickapp.com",
        EntryPublicKeyBase58Check: "BC1YLhMhapdhZQPytVRPDGTDtzcW79AfZXK1sqYXX1JdP6Y2tyBdXqu",
        OwnerPublicKeyBase58Check: "BC1YLiJA63MJiqdKdrm3zfQkSH5ZQqHaq2JEANRefWe96JdG68isbZs",
    },
    6: {
        Active: false,
        Name: "tijn's club",
        Owner: "tijn",
        URL: "https://tijn.club",
        FrontendURL: "https://tijn.club",
        EntryPublicKeyBase58Check: "BC1YLgLQ2igM9uMAWoQQVkwaQogaNRdm5114tuJHYCXoghnmiaY7vmN",
        OwnerPublicKeyBase58Check: "BC1YLgxLrxvq5mgZUUhJc1gkG6pwrRCTbdT6snwcrsEampjqnSD1vck",
    },
    7: {
        Active: false,
        Name: "Nacho Average",
        Owner: "ClayPerryMusic",
        URL: "https://nachoaverage.com",
        FrontendURL: "https://nachoaverage.com",
        EntryPublicKeyBase58Check: "BC1YLhebN4AuM9yycvDyMcDmuRwKuyZUiigMrGv7zVosUK2mcwjw2NJ",
        OwnerPublicKeyBase58Check: "BC1YLiUAXYJEqC1UzDvZB8Co5EidrLFb4VJ5bNZruTtGyBBPhsG2Jkr",
    },
    8: {
        Active: false,
        Name: "DeSoLabs",
        Owner: "kanshi",
        URL: "https://node.desolabs.org",
        FrontendURL: "https://node.desolabs.org",
        EntryPublicKeyBase58Check: "BC1YLjBvzHjemzgY4va55AzZ7VhRBLDmjxsfxRHQ9PybPARMQvtDH5N",
        OwnerPublicKeyBase58Check: "BC1YLhwpmWkgk2iM9yTSxzgUVhYjgessSPTiVHkkK9pMrhweqJnWrvK",
    },
    9: {
        Active: false,
        Name: "Supernovas",
        Owner: "fransarthur",
        URL: "https://supernovas.app",
        FrontendURL: "https://supernovas.app",
        EntryPublicKeyBase58Check: "BC1YLi2Xrz9CAxwUuJuvvptNRkEXycCLMyePmPmhF33Q5t7Gtn1TgBm",
        OwnerPublicKeyBase58Check: "BC1YLgBZL9X2GsE4WVNAaQcS6mEyDdAh5Jq4RkJ7aA8uM4DZuwzBsth",
    },
    10: {
        Active: false,
        Name: "GiftClout",
        Owner: "RajLahoti",
        URL: "https://members.giftclout.com",
        FrontendURL: "https://members.giftclout.com",
        EntryPublicKeyBase58Check: "BC1YLgcp38dQfgRvPvZkbpZKxCtNYgm89V6xNDqo5QnucWQSPM8nNXy",
        OwnerPublicKeyBase58Check: "BC1YLiRgvtCW3vwhy8jYahJoi5XmbrxSHrZHVPLBJm3cxWDKQ9vvwE8",
    },
    11: {
        Active: true,
        Name: "DeSocialWorld",
        Owner: "edokoevoet",
        URL: "https://desocialworld.com",
        FrontendURL: "https://desocialworld.com",
        EntryPublicKeyBase58Check: "BC1YLjSGY3DETtVTsiDVkobtvfDDtMuTjFoG1rmSagtWPzHyEZ3BKuB",
        OwnerPublicKeyBase58Check: "BC1YLhFjF9RXnpQitSLX4DytEgFFesfRFBBqq3FCBZ4YzJhTRmF39dt",
    },
    12: {
        Active: true,
        Name: "NFTz",
        Owner: "mvanhalen",
        URL: "https://validator.nftz.me",
        FrontendURL: "https://nftz.me",
        EntryPublicKeyBase58Check: "BC1YLhjjhom1dQXdW52ZoXUxTZQJrLaUH4mRfJBkNTiJYCMu7oCZC4d",
        OwnerPublicKeyBase58Check: "BC1YLfz7x1nT4dSAppTFTzhUNtSgwWria5E8ADEYzwAKEbSj51T72BM",
    },
    13: {
        Active: false,
        Name: "Cloutible",
        Owner: "DawaynePerza",
        URL: "https://cloutible.club",
        FrontendURL: "https://cloutible.club",
        EntryPublicKeyBase58Check: "BC1YLfkULpmqpbUtu5CCDfkGttP1dZFmTt23udEvBZ8bei5Sakk89cj",
        OwnerPublicKeyBase58Check: "BC1YLhSNTinvG9jau53eC1iTLdmQnt8v6qvJoFRY4hc3GNu3shHA89g",
    },
    14: {
        Active: true,
        Name: "Agbegbe",
        Owner: "TheParkerazzi",
        FrontendURL: "https://agbegbe.org",
        EntryPublicKeyBase58Check: "BC1YLhYx7GbSdoETTV3zhf7wkJsUUXZo6voQpQEZkYHKuovnENzDXRh",
        OwnerPublicKeyBase58Check: "BC1YLikxVjpkWuP3obWmKjB6XgpQWgMPz9ksRkfaLhdXaLpZyD8156B",
    },
    15: {
        Active: false,
        Name: "CloutingAround",
        Owner: "TheParkerazzi",
        URL: "https://cloutingaround.dev",
        FrontendURL: "https://cloutingaround.dev",
        EntryPublicKeyBase58Check: "BC1YLhmn94rDKdke9mFtJqJd1ZaV9hC1pUghEQCfChPxk9GzjA9Qxm8",
        OwnerPublicKeyBase58Check: "BC1YLikxVjpkWuP3obWmKjB6XgpQWgMPz9ksRkfaLhdXaLpZyD8156B",
    },
    16: {
        Active: false,
        Name: "MediaTech",
        Owner: "paulobrien",
        URL: "https://deso.mediatech.ventures",
        FrontendURL: "https://deso.mediatech.ventures",
        EntryPublicKeyBase58Check: "BC1YLhvkWv4x2fVKYKDSENVDYh9CCDBCgV51a8SJekYX3yZVqcDcpwj",
        OwnerPublicKeyBase58Check: "BC1YLg31719VWmDJ3jzuUEybXbQMof8jM9ATKcd95U4iwcHZs7vnoHo",
    },
    17: {
        Active: true,
        Name: "Mousai",
        Owner: "marlonjm2k",
        FrontendURL: "https://mousai.stream",
        EntryPublicKeyBase58Check: "BC1YLgTyYM1fFZZigu58Befs9MhnWugUBJ8VYXwYhNdPQLZvzETivM6",
        OwnerPublicKeyBase58Check: "BC1YLgVXZJ4QTUtF5CikfKCcxCaunaxqLdzS36SePz8LhJ6ULSKZy1D",
    },
    18: {
        Active: false,
        Name: "KoalaTBooks",
        Owner: "chriscelaya",
        URL: "https://koalatbooks.com",
        FrontendURL: "https://koalatbooks.com",
        EntryPublicKeyBase58Check: "BC1YLj7GDD7ANS2F2fiwUuUFbaGDvd8LDDMx6n1jxrfVZmHf5T3H3yb",
        OwnerPublicKeyBase58Check: "BC1YLfoXkBqLnj9uakEGqsSTF54Hyav6pYiVFjyjG1K7dP9E1DkFdZN",
    },
    19: {
        Active: false,
        Name: "Beyond",
        Owner: "RestartU",
        URL: "https://beyond.restartu.org",
        FrontendURL: "https://beyond.restartu.org",
        EntryPublicKeyBase58Check: "BC1YLjXyjGGx8mcmgD53DeN7rU6w4DXF4JAE3m1sZ7f9DjqLPbdU9Q9",
        OwnerPublicKeyBase58Check: "BC1YLjUkjZU9zB2FVLJ193m8fa4PHqMa5TY4F2iZgdJV9Bhe6vT8gRw",
    },
    20: {
        Active: false,
        Name: "DeverSo",
        Owner: "Nordian",
        URL: "https://deverso.io",
        FrontendURL: "https://deverso.io",
        EntryPublicKeyBase58Check: "BC1YLhzWG65PaGKy5csJT5m9zSviJqEkMWNeSMf3J5tAVA8tWto6CCg",
        OwnerPublicKeyBase58Check: "BC1YLh22xvrBkQZbxJWiF4G1X2bYHzRTvE8Cu3rHPNZQSHLUPnR8768",
    },
    21: {
        Active: false,
        Name: "VoSocial",
        Owner: "voso",
        URL: "https://vosoapp.com",
        FrontendURL: "https://vosoapp.com",
        EntryPublicKeyBase58Check: "BC1YLhU5jX8jCsoFXw4416zSmjyiGSxxbiEJmwmcaeKMKirSj4jveYZ",
        OwnerPublicKeyBase58Check: "BC1YLhU5jX8jCsoFXw4416zSmjyiGSxxbiEJmwmcaeKMKirSj4jveYZ",
    },
    22: {
        Active: false,
        Name: "Tunel",
        Owner: "hazrodriguez",
        FrontendURL: "https://tunel.app",
        EntryPublicKeyBase58Check: "BC1YLgLduMMHVefNjtpvZjTpX9QxSxW8wn6WcfHwyziGxsHuPWBBXc3",
        OwnerPublicKeyBase58Check: "BC1YLhMAJLqN3LksgxnyR5qQCkS6ccwxcANsEVBCH7saP7gcQ44HAux",
    },
    23: {
        Active: false, // is this still a deso project?
        Name: "Entre",
        Owner: "entre",
        URL: "https://joinentre.com",
        FrontendURL: "https://joinentre.com",
        EntryPublicKeyBase58Check: "BC1YLgy34m4qrufdBTBjXbdUqVPSdL6pCeoXHU3qquaUahsGPvAmzw5",
        OwnerPublicKeyBase58Check: "BC1YLgy34m4qrufdBTBjXbdUqVPSdL6pCeoXHU3qquaUahsGPvAmzw5",
    },
    24: {
        Active: false,
        Name: "Elmas",
        Owner: "elmas",
        URL: "https://elmas.app",
        FrontendURL: "https://elmas.app",
        EntryPublicKeyBase58Check: "BC1YLjVfcEmFtVb9KwZU9nzG1v4vGTufsMzR4YNPUxDCEoWpcLRNuwx",
        OwnerPublicKeyBase58Check: "BC1YLjVfcEmFtVb9KwZU9nzG1v4vGTufsMzR4YNPUxDCEoWpcLRNuwx",
    },
    25: {
        Active: false,
        Name: "İnci",
        Owner: "inci",
        URL: "https://inci.app",
        FrontendURL: "https://inci.app",
        EntryPublicKeyBase58Check: "BC1YLgVZs84qRgbds4DWdpbhWUACFarp1QCCjo5y1AcXAcpv5p8w4U6",
        OwnerPublicKeyBase58Check: "BC1YLgVZs84qRgbds4DWdpbhWUACFarp1QCCjo5y1AcXAcpv5p8w4U6",
    },
    26: {
        Active: false,
        Name: "Overclout",
        Owner: "Overclout",
        URL: "https://overclout.com",
        FrontendURL: "https://overclout.com",
        EntryPublicKeyBase58Check: "BC1YLhyHhMeL8bnHHxrbFjp6wvYWADu5mtzXZ1fbdpMKcHWUEd4s4pg",
        OwnerPublicKeyBase58Check: "BC1YLhyHhMeL8bnHHxrbFjp6wvYWADu5mtzXZ1fbdpMKcHWUEd4s4pg",
    },
    27: {
        Active: true,
        Name: "DesoNoCode",
        Owner: "DeSoNoCode",
        URL: "https://node.desonocode.com",
        FrontendURL: "https://node.desonocode.com",
        EntryPublicKeyBase58Check: "BC1YLgVazVu1yqb9ZdtyMezJ42ugZQzy9MCJUUtEuvKthMLqop3YGxp",
        OwnerPublicKeyBase58Check: "BC1YLgVazVu1yqb9ZdtyMezJ42ugZQzy9MCJUUtEuvKthMLqop3YGxp",
    },
    28: {
        Active: true,
        Name: "Post2EarnDao",
        Owner: "edokoevoet",
        URL: "https://node.post2earndao.com",
        FrontendURL: "https://post2earndao.com",
        EntryPublicKeyBase58Check: "BC1YLihgD73DorR8WcV4HCTxpUePaL8ABnF43KwE3H5SWvK7bTuLCuL",
        OwnerPublicKeyBase58Check: "BC1YLhFjF9RXnpQitSLX4DytEgFFesfRFBBqq3FCBZ4YzJhTRmF39dt",
    },
    29: {
        Active: false,
        Name: "Pearl",
        Owner: "pearl",
        FrontendURL: "https://pearl.app",
        EntryPublicKeyBase58Check: "BC1YLjFYcyrfzZBxaQAAtuKnHTE9t8ozbX6VqvN3Ryza8z2cnUAPR7J",
        OwnerPublicKeyBase58Check: "BC1YLjFYcyrfzZBxaQAAtuKnHTE9t8ozbX6VqvN3Ryza8z2cnUAPR7J",
    },
    30: {
        Active: true,
        Name: "Focus",
        Owner: "nader",
        URL: "https://focus.xyz",
        FrontendURL: "https://focus.xyz",
        GraphqlURL: "https://graphql.focus.xyz/graphql",
        EntryPublicKeyBase58Check: "BC1YLgCHoNcwi8h6gQ8ajayqN6BELu11jc2C5A7jPUgPT253xL3jXUq",
        OwnerPublicKeyBase58Check: "BC1YLhyuDGeWVgHmh3UQEoKstda525T1LnonYWURBdpgWbFBfRuntP5",
    },
    31: {
        Active: true,
        Name: "SafetyNet",
        Owner: "SafetyNet",
        URL: "https://validator.safetynet.social",
        FrontendURL: "https://safetynet.social",
        GraphqlURL: "https://graphql.safetynet.social",
        EntryPublicKeyBase58Check: "BC1YLh99esxXJi1DnVKd7GUMnm9GXCzeLTLq4zu6g5JEvWgDLQpoS9v",
        OwnerPublicKeyBase58Check: "BC1YLh99esxXJi1DnVKd7GUMnm9GXCzeLTLq4zu6g5JEvWgDLQpoS9v",
    },
    32: {
        Active: true,
        Name: "BeyondSocial",
        Owner: "StarGeezer",
        FrontendURL: "https://beyondsocial.app",
        EntryPublicKeyBase58Check: "BC1YLg6ZPmoFXwdRMe7EhnuJJJmbckATPpbK3Cy9miH6WSE4UWBzz2u",
        OwnerPublicKeyBase58Check: "BC1YLjWERF3xWcAD3SeCqtnRwF3FvhoXScZmF5TECd98qeCZpEzgsJD",
    }

// Note the following unregistered entries exist in transactions on the blockchain
//
// NOTE: following was USING #30, but #30 is now registered as focus.xyz
//    30: {
//        Active: false,
//        Name: "CooperativaLocal",
//        Owner: "CooperativaLocal",
//        URL: "https://node.cooperativalocal.org",
//        FrontendURL: "https://node.cooperativalocal.org",
//        EntryPublicKeyBase58Check: "BC1YLjFYcyrfzZBxaQAAtuKnHTE9t8ozbX6VqvN3Ryza8z2cnUAPR7J",
//        OwnerPublicKeyBase58Check: "BC1YLjFYcyrfzZBxaQAAtuKnHTE9t8ozbX6VqvN3Ryza8z2cnUAPR7J",
//    },
// NOTE: following USING 30, not a node and #30 is now registered as focus.xyz
//    30: {
//        Active: true,
//        Name: "MyDeSoSpace",
//        Owner: "nathanwells",
//        FrontendURL: "https://mydesospace.com",
//        EntryPublicKeyBase58Check: "BC1YLfzejg1ak9KuSDchYpwT9VGjwmyVWH1GCHJRRoaPbkJezG5pCRA",
//        OwnerPublicKeyBase58Check: "BC1YLh3xfZeXxLNnMaMwhvnTBWozbyoWbDzzyk5ydh6rikNdzPuYEY4",
//    }
}
