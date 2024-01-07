package constraint

// BlueprintGenericR1C implements Blueprint and BlueprintR1C.
// Encodes
//
//	L * R == 0
type BlueprintGenericR1C struct{}

func (b *BlueprintGenericR1C) CalldataSize() int {
	// size of linear expressions are unknown.
	return -1
}
func (b *BlueprintGenericR1C) NbConstraints() int {
	return 1
}
func (b *BlueprintGenericR1C) NbOutputs(inst Instruction) int {
	return 0
}

/*
将R1CS 转化为instruction([]uint32)表示，, 表示方法为
uint32[0] : 总共的uint32长度
uint32[1]:  x 中元素的个数
uint32[2]:  y 中元素的个数
uint32[3]:  c 中元素的个数
uint32[4]:  x0 系数索引
uint32[5]:  x0 变量索引
 .......
 例如：对于 (1·x0+2·x1) + (3·y0+4·y1+5·y2) = 6·c0，他的[]uint32 是
  [16][2][3][1][系数1的ID][变量x0的ID][系数2的ID][变量x1的ID][系数3的ID][变量y0的ID][系数4的ID][][变量y1的ID][系数5的ID][变量y2的ID][系数6的ID][变量c0的ID]
*/

func (b *BlueprintGenericR1C) CompressR1C(c *R1C, to *[]uint32) {
	// we store total nb inputs, len L, len R, len O, and then the "flatten" linear expressions
	nbInputs := 4 + 2*(len(c.L)+len(c.R)+len(c.O))
	(*to) = append((*to), uint32(nbInputs))
	(*to) = append((*to), uint32(len(c.L)), uint32(len(c.R)), uint32(len(c.O)))
	for _, t := range c.L {
		(*to) = append((*to), uint32(t.CoeffID()), uint32(t.WireID()))
	}
	for _, t := range c.R {
		(*to) = append((*to), uint32(t.CoeffID()), uint32(t.WireID()))
	}
	for _, t := range c.O {
		(*to) = append((*to), uint32(t.CoeffID()), uint32(t.WireID()))
	}
}

// 将instruction 解压成R1CS
func (b *BlueprintGenericR1C) DecompressR1C(c *R1C, inst Instruction) {
	copySlice := func(slice *LinearExpression, expectedLen, idx int) {
		if cap(*slice) >= expectedLen {
			(*slice) = (*slice)[:expectedLen]
		} else {
			(*slice) = make(LinearExpression, expectedLen, expectedLen*2)
		}
		for k := 0; k < expectedLen; k++ {
			(*slice)[k].CID = inst.Calldata[idx]
			idx++
			(*slice)[k].VID = inst.Calldata[idx]
			idx++
		}
	}

	lenL := int(inst.Calldata[1]) //L的元素个数
	lenR := int(inst.Calldata[2]) //R的元素个数
	lenO := int(inst.Calldata[3]) //O的元素个数

	const offset = 4 //从第4个[]uint32开始
	copySlice(&c.L, lenL, offset)
	copySlice(&c.R, lenR, offset+2*lenL)
	copySlice(&c.O, lenO, offset+2*(lenL+lenR))
}

func (b *BlueprintGenericR1C) UpdateInstructionTree(inst Instruction, tree InstructionTree) Level {
	// a R1C doesn't know which wires are input and which are outputs
	lenL := int(inst.Calldata[1])
	lenR := int(inst.Calldata[2])
	lenO := int(inst.Calldata[3])

	outputWires := make([]uint32, 0) //记录还没有登记在册的变量ID
	maxLevel := LevelUnset
	walkWires := func(n, idx int) { //wires 就是变量ID
		for k := 0; k < n; k++ {
			wireID := inst.Calldata[idx+1]
			idx += 2 // advance the offset (coeffID + wireID)
			if !tree.HasWire(wireID) {
				continue
			}
			if level := tree.GetWireLevel(wireID); level == LevelUnset {
				outputWires = append(outputWires, wireID)
			} else if level > maxLevel {
				maxLevel = level
			}
		}
	}

	const offset = 4
	walkWires(lenL, offset)
	walkWires(lenR, offset+2*lenL)
	walkWires(lenO, offset+2*(lenL+lenR))

	// insert the new wires.
	maxLevel++
	for _, wireID := range outputWires {
		tree.InsertWire(wireID, maxLevel)
	}

	return maxLevel
}
