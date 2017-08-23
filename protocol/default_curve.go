package protocol

import "github.com/dedis/paper_17_dfinity/pbc"

// Ugly hack to have a fixed pairing for compile time since switching at runtime
// does segfault for the moment. See https://github.com/dfinity/bn/issues/8 .
var pairing = pbc.NewPairingFp254BNb()
