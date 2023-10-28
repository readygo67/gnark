package lzss_v2

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark/std/compress/lzss_v2/suffixarray"
)

const (
	nbBytesAddress = 3
	nbBytesLength  = 1
	maxInputSize   = 1 << 21 // 2Mb
	maxDictSize    = 1 << 22 // 4Mb
)

func (compressor *Compressor) Compress(d []byte) (c []byte, err error) {
	compressor.out.Reset()

	if len(d) > maxInputSize {
		return nil, fmt.Errorf("input size must be <= %d", maxInputSize)
	}

	// copy d into compressor.data
	copy(compressor.data[len(compressor.dict):], d)
	compressor.end = len(compressor.dict) + len(d)

	// build the index
	compressor.index = suffixarray.New(compressor.data[:compressor.end])

	i := len(compressor.dict) // start after dict

	// under that threshold, it's more interesting to write the symbol directly.
	const t = int(1 + nbBytesAddress + nbBytesLength)

	for i < compressor.end {
		var addr, length int
		if compressor.data[i] == 0 {
			addr, length = compressor.longestMostRecentBackRef(i, 1)
			if length == -1 {
				// no backref found
				return nil, fmt.Errorf("could not find an RLE backref at index %d", i)
			}
		} else {
			addr, length = compressor.longestMostRecentBackRef(i, t)
			if length == -1 {
				compressor.out.WriteByte(compressor.data[i])
				i++
				continue
			}
			if length < 100 && i+1 < compressor.end {
				// let's try to find a better backref
				lazyAddr, lazyLength := compressor.longestMostRecentBackRef(i+1, t)
				if lazyLength > length {
					// we found a better backref
					// first emit the symbol at i
					compressor.out.WriteByte(compressor.data[i])
					i++

					// then emit the backref at i+1
					addr, length = lazyAddr, lazyLength

					// can we find an even better backref?
					if length < 100 && compressor.data[i] != 0 && i+1 < compressor.end {
						lazyAddr2, lazyLength2 := compressor.longestMostRecentBackRef(i+1, t)
						if lazyLength2 > lazyLength+1 {
							// we found an even better backref
							// write the symbol at i
							compressor.out.WriteByte(compressor.data[i])
							i++
							addr, length = lazyAddr2, lazyLength2
						}
					}
				} else {
					// maybe at i+2 ? (we already tried i+1)
					if compressor.data[i+1] != 0 && i+2 < compressor.end {
						lazyAddr2, lazyLength2 := compressor.longestMostRecentBackRef(i+2, t)
						if lazyLength2 > length+1 {
							// we found a better backref
							// write the symbol at i
							compressor.out.WriteByte(compressor.data[i])
							i++
							compressor.out.WriteByte(compressor.data[i])
							i++

							// then emit the backref at i+2
							addr, length = lazyAddr2, lazyLength2
						}
					}
				}
			}
		}

		compressor.emitBackRef(i-addr, length)
		i += length
	}

	return compressor.out.Bytes(), nil
}

type Compressor struct {
	data  [maxDictSize + maxInputSize]byte
	dict  []byte
	end   int
	index *suffixarray.Index
	out   bytes.Buffer
}

func NewCompressor(dict []byte) (*Compressor, error) {
	if len(dict) > maxDictSize {
		return nil, fmt.Errorf("dict size must be <= %d", maxDictSize)
	}
	c := &Compressor{
		dict: dict,
		end:  len(dict),
	}
	c.out.Grow(maxInputSize)
	copy(c.data[:], dict)
	return c, nil
}

func (compressor *Compressor) emitBackRef(offset, length int) {
	compressor.out.WriteByte(0)
	offset--
	length--
	for i := uint(0); i < nbBytesAddress; i++ {
		compressor.out.WriteByte(byte(offset))
		offset >>= 8
	}
	for i := uint(0); i < nbBytesLength; i++ {
		compressor.out.WriteByte(byte(length))
		length >>= 8
	}
}

// longestMostRecentBackRef attempts to find a backref that is 1) longest 2) most recent in that order of priority
func (compressor *Compressor) longestMostRecentBackRef(i, minRefLen int) (addr, length int) {
	d := compressor.data[:compressor.end]
	// var backRefLen int
	const brAddressRange = 1 << (nbBytesAddress * 8)
	const brLengthRange = 1 << (nbBytesLength * 8)
	minBackRefAddr := i - brAddressRange

	windowStart := max(0, minBackRefAddr)
	maxRefLen := brLengthRange // utils.Min(i+brLengthRange, len(d))
	if i+maxRefLen > len(d) {
		maxRefLen = len(d) - i
	}

	if i+minRefLen > len(d) {
		return -1, -1
	}

	addr, len := compressor.index.LookupLongest(d[i:i+maxRefLen], minRefLen, maxRefLen, windowStart, i)
	if len == -1 {
		return -1, -1
	}
	return addr, len

}
