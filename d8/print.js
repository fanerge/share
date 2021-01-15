// 查看V8优化细节
// d8 print.js --trace-opt-verbose
// 查看对应的字节码
// d8 print.js --print-bytecode

let a = {x:1}
function bar(obj) { 
  return obj.x 
}

function foo () { 
  let ret = 0
  // for(let i = 1; i < 7049; i++) {
  for(let i = 1; i < 100000; i++) {
    ret += bar(a)
  }
  return ret
}

foo()

// https://wingolog.org/archives/2011/06/20/on-stack-replacement-in-v8

/**
 * 执行次数为7049
 * 当 V8 先执行到这段代码的时候，监控到循环会一直被执行，于是判断这是一块热点代码，
 * 于是，V8 就会将热点代码编译为优化后的二进制代码。
 * 
 * 
 * 
 * 执行次数为100000
 * 这段提示是说，由于循环次数过多，V8 采取了 TurboFan 的 OSR 优化，OSR 全称是 On-Stack Replacement，
 * 它是一种在运行时替换正在运行的函数的栈帧的技术，如果在 foo 函数中，每次调用 bar 函数时，都要创建 bar 函数的栈帧，
 * 等 bar 函数执行结束之后，又要销毁 bar 函数的栈帧。
 * PS：Turbofan 是新的优化编译器，而 Ignition 则是新的解释器。
 * [V8官方blog](https://v8.dev/blog)
 * 
 * 通常情况下，这没有问题，但是在 foo 函数中，采用了大量的循环来重复调用 bar 函数，
 * 这就意味着 V8 需要不断为 bar 函数创建栈帧，销毁栈帧，那么这样势必会影响到 foo 函数的执行效率。
 * 于是，V8 采用了 OSR 技术，将 bar 函数和 foo 函数合并成一个新的函数。
 * 
 * 如果我在 foo 函数里面执行了 10 万次循环，在循环体内调用了 10 万次 bar 函数，那么 V8 会实现两次优化，
 * 第一次是将 foo 函数编译成优化的二进制代码，第二次是将 foo 函数和 bar 函数合成为一个新的函数。
 * [on-stack replacement in v8](https://wingolog.org/archives/2011/06/20/on-stack-replacement-in-v8)
 */
