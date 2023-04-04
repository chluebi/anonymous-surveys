export default {
  props: {
    question: Object
  },
  emits: ['selected', 'selectedother'],
  template: `
  <h2>{{ question.text }}</h2>
  <div :class="{button: true, selected: question.answer.answer === choice}"  @click="$emit('selected', choice)" v-for="choice in question.options.choices">
    {{ choice }}
  </div>
  <div v-if="question.options.textother" :class="{button: true, selected: question.answer.other }" @input="$emit('selectedother')" @click="$emit('selectedother')">
    <input type="text" id="choice-other">
  </div>
  `
}