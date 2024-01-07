package r1cs

// An minHeap is a min-heap of linear expressions. It facilitates merging k-linear expressions.
//
// The code is identical to https://pkg.go.dev/container/heap but replaces interfaces with concrete
// type to avoid memory overhead.
type minHeap []linMeta

func (h minHeap) less(i, j int) bool { return h[i].val < h[j].val }
func (h minHeap) swap(i, j int)      { h[i], h[j] = h[j], h[i] }

// heapify establishes the heap invariants required by the other routines in this package.
// heapify is idempotent with respect to the heap invariants
// and may be called whenever the heap invariants may have been invalidated.
// The complexity is O(n) where n = len(*h).
func (h *minHeap) heapify() {
	// heapify
	n := len(*h)
	for i := n/2 - 1; i >= 0; i-- {
		h.down(i, n)
	}
}

// push the element x onto the heap.
// The complexity is O(log n) where n = len(*h).
func (h *minHeap) push(x linMeta) {
	*h = append(*h, x) //将元素x添加到数组的末尾, 此时数组长度从n增加到n+1
	h.up(len(*h) - 1)  //对el[n+1-1] 这个元素进行上浮
}

// Pop removes and returns the minimum element (according to Less) from the heap.
// The complexity is O(log n) where n = len(*h).
// Pop is equivalent to Remove(h, 0).
func (h *minHeap) popHead() {
	n := len(*h) - 1 //获取最后一个元素的下标n-1
	h.swap(0, n)     //交换第el[0] el[n-1]
	h.down(0, n)     //调整el[0...n-2], 注意数组的长度已经减1了。
	*h = (*h)[0:n]
}

// fix re-establishes the heap ordering after the element at index i has changed its value.
// Changing the value of the element at index i and then calling fix is equivalent to,
// but less expensive than, calling Remove(h, i) followed by a Push of the new value.
// The complexity is O(log n) where n = len(*h).
func (h *minHeap) fix(i int) {
	if !h.down(i, len(*h)) {
		h.up(i)
	}
}

func (h *minHeap) up(j int) {
	for {
		i := (j - 1) / 2             // parent 获取el[j]的父节点el[i]
		if i == j || !h.less(j, i) { //如果el[j]不小于el[i], 则跳出循环
			break
		}
		h.swap(i, j) //
		j = i
	}
}

// n 数组的长度，对应的lastIndex=n-1
func (h *minHeap) down(i0, n int) bool {
	i := i0
	for {
		j1 := 2*i + 1          //左节点的下标， 如果左节点下标>=数组长度, 则跳出循环
		if j1 >= n || j1 < 0 { // j1 < 0 after int overflow
			break
		}
		j := j1 // left child
		if j2 := j1 + 1; j2 < n && h.less(j2, j1) {
			j = j2 // = 2*i + 2  // right child，取得左右子节点中较小的下标
		}
		if !h.less(j, i) { //如果子树中较小的下标不小于父节点下标, 则跳出循环
			break
		}
		h.swap(i, j) // 否则交换父节点和min(left, right)
		i = j        //重复检查
	}
	return i > i0 //当i >i0 时,返回true
}

// linMeta stores metadata to iterate over a linear expression
type linMeta struct {
	lID int // argument ID to retrieve the position of the list in the argument
	tID int // termID current iteration position (starts at 0)
	val int // current linearExp[tID].VID value
}
