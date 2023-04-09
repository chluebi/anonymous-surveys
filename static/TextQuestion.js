export default {
    props: {
      question: Object
    },
    emits: ['selected'],
    template: `
    <h2>{{ question.text }}</h2>
    <input type="text" id="input" :class="{button: true, selected: question.answer !== '' }" @input="$emit('selected')" @click="$emit('selected')">
    `
  }