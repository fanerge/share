
// d8 --trace-gc gc.js
// test1
// function strToArray(str) {
//     let i = 0
//     const len = str.length
//     let arr = new Uint16Array(str.length)
//     for (; i < len; ++i) {
//       arr[i] = str.charCodeAt(i)
//     }
//     return arr;
//   }
  
  
//   function foo() {
//     let i = 0
//     let str = 'test V8 GC'
//     while (i++ < 1e5) {
//       strToArray(str);
//     }
//   }
// foo()

// test2

function strToArray(str, bufferView) {
    let i = 0
    const len = str.length
    for (; i < len; ++i) {
      bufferView[i] = str.charCodeAt(i);
    }
    return bufferView;
  }
  function foo() {
    let i = 0
    let str = 'test V8 GC'
    let buffer = new ArrayBuffer(str.length * 2)
    let bufferView = new Uint16Array(buffer);
    while (i++ < 1e5) {
      strToArray(str,bufferView);
    }
  }
  foo()

  /***
   * // test1在循环中申请内存
   * 上面这段代码，我们重复将一段字符串转换为数组，并重复在堆中申请内存，将转换后的数组存放在内存中。
   * 我们可以通过trace-gc来查看这段代码的内存回收状态。
   * 
   * 这句话的意思是提示“Scavenge … 分配失败”，是因为垃圾回收器 Scavenge 所负责的空间已经满了，
   * Scavenge 主要回收 V8 中“新生代”中的内存，大多数对象都是分配在新生代内存中，内存分配到新生代中是非常快速的，
   * 但是新生代的空间却非常小，通常在 1～8 MB 之间，一旦空间被填满，Scavenge 就会进行“清理”操作。
   * 
   * // test2
   * 我们将 strToArray 中分配的内存块，提前到了 foo 函数中分配，这样我们就不需要每次在 strToArray 函数分配内存了，
   * 再次执行trace-gc的命令：
   * 我们就会看到，这时候没有任何垃圾回收的提示了，这也意味着这时没有任何垃圾分配的操作了。
   */