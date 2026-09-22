import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata={title:"TuCasa — Find your night",description:"Discover, join, host and remember parties with TuCasa."};
export default function RootLayout({children}:{children:React.ReactNode}){return <html lang="en"><body>{children}</body></html>}