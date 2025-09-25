import type {
	CardListData,
	Config,
	IntegrationUserConfig,
	ThemeUserConfig,
} from "astro-pure/types";

export const theme: ThemeUserConfig = {
	// === Basic configuration ===
	/** Title for your website. Will be used in metadata and as browser tab title. */
	title: "Swizzer's Sound",
	/** Will be used in index page & copyright declaration */
	author: "Swizzer",
	/** Description metadata for your website. Can be used in page metadata. */
	description: "No, thank you!",
	/** The default favicon for your site which should be a path to an image in the `public/` directory. */
	favicon: "/favicon/favicon.png",
	/** Specify the default language for this site. */
	locale: {
		lang: "en-US",
		attrs: "en_US",
		// Date locale
		dateLocale: "en-US",
		dateOptions: {
			day: "numeric",
			month: "short",
			year: "numeric",
		},
	},
	/** Set a logo image to show in the homepage. */
	logo: {
		src: "src/assets/avatar.jpg",
		alt: "Avatar",
	},

	// === Global configuration ===
	titleDelimiter: "•",
	prerender: true,
	npmCDN: "https://cdn.jsdelivr.net/npm",

	// Still in test
	head: [
		/* Telegram channel */
		// {
		//   tag: 'meta',
		//   attrs: { name: 'telegram:channel', content: '@cworld0_cn' },
		//   content: ''
		// }
	],
	customCss: [],

	/** Configure the header of your site. */
	header: {
		menu: [
			{ title: "Blog", link: "/blog" },
			{ title: "Diary", link: "/diary" },
			{ title: "Links", link: "/links" },
			{ title: "About", link: "/about" },
		],
	},

	/** Configure the footer of your site. */
	footer: {
		// Year format
		year: `© ${new Date().getFullYear()}`,
		// year: `© 2019 - ${new Date().getFullYear()}`,
		links: [],
		/** Enable displaying a “Astro & Pure theme powered” link in your site’s footer. */
		credits: false,
		/** Optional details about the social media accounts for this site. */
		social: {
			github: "https://github.com/Swizzzer",
			bilibili: "https://space.bilibili.com/446708215",
			x: "https://x.com/obfusor",
		},
	},

	content: {
		/** External links configuration */
		externalLinks: {
			content: " ↗",
			/** Properties for the external links element */
			properties: {
				style: "user-select:none",
			},
		},
		/** Blog page size for pagination (optional) */
		blogPageSize: 8,
		// Currently support weibo, x, bluesky
		share: ["weibo", "x", "bluesky"],
	},
};

export const integ: IntegrationUserConfig = {
	// Links management

	links: {
		// Friend logbook
		logbook: [],
		// Yourself link info
		applyTip: [
			{ name: "Name", val: theme.title },
			{ name: "Desc", val: theme.description || "Null" },
			{ name: "Link", val: "https://blog.swizzer.cc/" },
			{ name: "Avatar", val: "https://pic.swizzer.cc/avatar.jpg" },
		],
	},
	// Enable page search function
	pagefind: true,
	// UnoCSS typography
	// See: https://unocss.dev/presets/typography
	typography: {
		class: "prose text-base text-muted-foreground",
		// The style of blockquote font, normal or italic (default to italic in typography)
		blockquoteStyle: "italic",
		// The style of inline code block, code or modern (default to code in typography)
		inlineCodeBlockStyle: "modern",
	},
	// A lightbox library that can add zoom effect
	mediumZoom: {
		enable: true, // disable it will not load the whole library
		selector: ".prose .zoomable",
		options: {
			className: "zoomable",
		},
	},
	// Comment system
	waline: {
		enable: true,
		// Server service link
		server: "https://comment.swizzer.cc/",
		// Refer https://waline.js.org/en/guide/features/emoji.html
		emoji: ["bmoji", "weibo"],
		// Refer https://waline.js.org/en/reference/client/props.html
		additionalConfigs: {
			// search: false,
			pageview: true,
			comment: true,
			locale: {
				reaction0: "Like",
				placeholder:
					"Welcome to comment. (Email to receive replies. Login is unnecessary)",
			},
			imageUploader: false,
		},
	},
};

const config = { ...theme, integ } as Config;
export default config;
