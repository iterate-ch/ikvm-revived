/*
  Copyright (C) 2007-2015 Jeroen Frijters
  Copyright (C) 2009 Volker Berlin (i-net software)

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Jeroen Frijters
  jeroen@frijters.net
  
*/

namespace IKVM.Java.Externs.sun.net
{

    static class ExtendedOptionsImpl
    {

        public static void init()
        {

        }

        public static void setFlowOption(global::java.io.FileDescriptor fd, object f)
        {
#if !FIRST_PASS
            throw new global::java.lang.UnsupportedOperationException();
#endif
        }

        public static void getFlowOption(global::java.io.FileDescriptor fd, object f)
        {
#if !FIRST_PASS
            throw new global::java.lang.UnsupportedOperationException();
#endif
        }

        public static void setTcpKeepAliveProbes(global::java.io.FileDescriptor fd, int i)
        {
#if !FIRST_PASS
            throw new global::java.lang.UnsupportedOperationException();
#endif
        }

        public static void setTcpKeepAliveTime(global::java.io.FileDescriptor fd, int i)
        {
#if !FIRST_PASS
            throw new global::java.lang.UnsupportedOperationException();
#endif
        }

        public static void setTcpKeepAliveIntvl(global::java.io.FileDescriptor fd, int i)
        {
#if !FIRST_PASS
            throw new global::java.lang.UnsupportedOperationException();
#endif
        }

        public static int getTcpKeepAliveProbes(global::java.io.FileDescriptor fd)
        {
            return 0;
        }

        public static int getTcpKeepAliveTime(global::java.io.FileDescriptor fd)
        {
            return 0;
        }

        public static int getTcpKeepAliveIntvl(global::java.io.FileDescriptor fd)
        {
            return 0;
        }

        public static bool flowSupported()
        {
            // We don't support this. Solaris only functionality.
            return false;
        }

        public static bool keepAliveOptionsSupported()
        {
            // We don't support this. Solaris only functionality.
            return false;
        }

    }

}
