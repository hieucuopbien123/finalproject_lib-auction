const Header = require('./src/header')
const BSCMainnetHeader = require("./src/bscmainnetheader");
const BSCTestnetHeader = require("./src/bsctestnetheader");
const GoerliHeader = require("./src/goerliheader");
const SepoliaHeader = require("./src/sepoliaheader");
const Proof = require('./src/proof')
const EthObject = require('./src/ethObject')

module.exports = { Header, BSCMainnetHeader, BSCTestnetHeader, GoerliHeader, SepoliaHeader, Proof, EthObject }
