package lib

type DeSoNode struct {
	Name  string
	URL   string
	Owner string
}

var NODES = map[uint64]DeSoNode{
	1: {
		Name:  "DeSo",
		URL:   "https://node.deso.org",
		Owner: "diamondhands",
	},
	2: {
		Name:  "BitClout",
		URL:   "https://bitclout.com",
		Owner: "diamondhands",
	},
	3: {
		Name:  "Diamond",
		URL:   "https://diamondapp.com",
		Owner: "Zordon",
	},
	4: {
		Name:  "CloutFeed",
		URL:   "https://apps.apple.com/app/id1561532815",
		Owner: "Ribal",
	},
	5: {
		Name:  "Flick",
		URL:   "https://flickapp.com",
		Owner: "nigeleccles",
	},
	6: {
		Name:  "tijn's club",
		URL:   "https://tijn.club",
		Owner: "tijn",
	},
	7: {
		Name:  "Nacho Average",
		URL:   "https://nachoaverage.com/",
		Owner: "ClayPerryMusic",
	},
	8: {
		Name:  "love4src",
		URL:   "https://love4src.com",
		Owner: "kanshi",
	},
	9: {
		Name:  "Supernovas",
		URL:   "https://supernovas.app",
		Owner: "fransarthur",
	},
	10: {
		Name:  "GiftClout",
		URL:   "https://members.giftclout.com",
		Owner: "RajLahoti",
	},
}
