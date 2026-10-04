/**
 * Shared by the SVG line chart and the two charts that use it.
 *
 * Kept out of the component because `<script setup>` cannot export anything.
 */
export interface ChartSeries {
  /** Already translated; used by the legend and the hover readout. */
  name: string
  color: string
  values: number[]
  /** Fill under the line with a gradient of the series colour. */
  area?: boolean
}
