// 独立脚本: 用 star-history 开源逻辑生成 Marven11/Fenjing 的 star 历史 SVG。
//
// 设计: 此脚本放在 fenjing 仓库 .github/scripts/ 下。GitHub Action 运行时:
//   1. git clone star-history/star-history 到 /tmp/sh
//   2. cp 本脚本到 /tmp/sh/backend/
//   3. 在 /tmp/sh 安装依赖、用 tsx 运行本脚本,把 stdout 重定向到 stars.svg
//
// 直接 import star-history 仓库的 shared 模块,不启动 backend server,不部署任何服务。
// 这样图表样式与 star-history 官网完全一致,且 token 始终留在 Action runner 本地。
//
// 环境变量:
//   GITHUB_TOKEN  必填,有目标 repo metadata 读权限的 GitHub token
//   REPO          可选,默认 Marven11/Fenjing
//   CHART_WIDTH   可选,默认 800
//   THEME         可选,"light" | "dark",默认 "light"
import { JSDOM } from "jsdom";
import { optimize } from "svgo";
import XYChart from "../shared/packages/xy-chart.js";
import { convertDataToChartData, getRepoData } from "../shared/common/chart.js";
import { fixJsdomSvgCasing } from "./utils.js";

const REPO = process.env.REPO || "Marven11/Fenjing";
const TOKEN = process.env.GITHUB_TOKEN!;
const MAX_REQUEST_AMOUNT = 16;
const WIDTH = Number(process.env.CHART_WIDTH || "800");
const THEME = process.env.THEME === "dark" ? "dark" : "light";

if (!TOKEN) {
  console.error("ERROR: GITHUB_TOKEN env var not set");
  process.exit(1);
}

async function main() {
  console.error(`[gen] fetching star data for ${REPO} (theme=${THEME}) ...`);
  const repoData = await getRepoData([REPO], TOKEN, MAX_REQUEST_AMOUNT);
  console.error(`[gen] got ${repoData[0].starRecords.length} star records`);

  const dom = new JSDOM(`<!DOCTYPE html><body></body>`);
  const body = dom.window.document.querySelector("body")!;
  const svg = dom.window.document.createElement("svg") as unknown as SVGSVGElement;
  body.append(svg);
  svg.setAttribute("width", `${WIDTH}`);
  svg.setAttribute("xmlns", "http://www.w3.org/2000/svg");

  XYChart(
    svg,
    {
      title: "Star History",
      xLabel: "Date",
      yLabel: "GitHub Stars",
      data: convertDataToChartData(repoData, "Date"),
      showDots: false,
      transparent: false,
      theme: THEME,
    },
    {
      xTickLabelType: "Date",
      chartWidth: WIDTH,
      useLogScale: false,
      legendPosition: "top-left",
    }
  );

  const svgContent = fixJsdomSvgCasing(svg.outerHTML);
  const optimized = optimize(svgContent, { multipass: true }).data;
  process.stdout.write(optimized);
  console.error(`[gen] done, svg size: ${optimized.length} bytes`);
}

main().catch((e) => {
  console.error("[gen] FAILED:", e);
  process.exit(1);
});
