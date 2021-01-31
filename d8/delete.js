// d8 delete.js --allow-natives-syntax
// 所有可使用的 V8 内部方法
// https://github.com/v8/v8/blob/4b9b23521e6fd42373ebbcb20ebe03bf445494f9/src/runtime/runtime.h
// delete 
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
  var bar = new Foo(10,10)
  console.log(%HasFastProperties(bar));
  // delete bar[0] // 删除可索引属性，不影响
  // delete bar.property2 // 删除非最后添加的常规属性，影响
  // delete bar.property9 // 删除最后添加的常规属性，影响
  // bar.property2 = null // 将常规属性赋值为 null，不影响
  // bar.property2 = undefined // 将常规属性赋值为 undefined，不影响
  console.log(%HasFastProperties(bar));