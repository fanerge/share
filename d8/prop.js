// 什么是常规属性 (properties) 和排序属性 (elements)？ 

// function Foo() {
//     this[100] = 'test-100'
//     this[1] = 'test-1'
//     this["B"] = 'bar-B'
//     this[50] = 'test-50'
//     this[9] =  'test-9'
//     this[8] = 'test-8'
//     this[3] = 'test-3'
//     this[5] = 'test-5'
//     this["A"] = 'bar-A'
//     this["C"] = 'bar-C'
//     // return this;
// }
// var bar = new Foo()

// for(key in bar){
//     console.log(`index:${key}  value:${bar[key]}`)
// }

/**
 * 在上面这段代码中，我们利用构造函数 Foo 创建了一个 bar 对象，在构造函数中，
 * 我们给 bar 对象设置了很多属性，包括了数字属性和字符串属性，然后我们枚举出来了 bar 对象中所有的属性，
 * 并将其一一打印出来，下面就是执行这段代码所打印出来的结果。
 * 顺序有一下两个特点：
 * 1.   设置的数字属性被最先打印出来了，并且是按照数字大小的顺序打印的；
 * 2.   设置的字符串属性依然是按照之前的设置顺序打印的，比如我们是按照 B、A、C 的顺序设置的，打印出来依然是这个顺序。
 * 
 * 因为：ECMAScript 规范中定义了数字属性应该按照索引值大小升序排列，字符串属性根据创建时的顺序升序排列。
 * 在这里我们把对象中的数字属性称为排序属性，在 V8 中被称为 elements，字符串属性就被称为常规属性，在 V8 中被称为 properties。
 */


function Foo(property_num,element_num) {
    //添加可索引属性
    for (let i = 0; i < element_num; i++) {
        this[i] = `element${i}`
    }
    //添加常规属性
    for (let i = 0; i < property_num; i++) {
        let ppt = `property${i}`
        this[ppt] = ppt
    }
}
// var bar1 = new Foo(10,10)
// var bar2 = new Foo(20,10)
// var bar3 = new Foo(100,10)