export default {
    props: {
      question: Object
    },
    emits: ['selectedother'],
    template: `
    <h2>{{ question.text }}</h2>
    <div :class="{button: true, selected: question.answer.other }" @input="$emit('selectedother')" @click="$emit('selectedother')">
      <input type="text" id="choice-other">
    </div>
    `
  }