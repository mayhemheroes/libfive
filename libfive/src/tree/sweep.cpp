/*
libfive: a CAD kernel for modeling with implicit functions
Copyright (C) 2017  Matt Keeter

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include <array>

#include "libfive/tree/sweep.hpp"
#include "libfive/tree/oracle_clause_bezier.hpp"

namespace Kernel {

Tree sweep(Tree input, const Eigen::Vector3f& a,
                       const Eigen::Vector3f& b,
                       const Eigen::Vector3f& c)
{
    Bezier bezier(a, b, c);
    Tree t(std::unique_ptr<BezierClosestPointOracleClause>(
            new BezierClosestPointOracleClause(bezier)));

    std::array<Tree, 3> remapped = {{ Tree::X(), Tree::Y(), Tree::Z() }};
    for (unsigned i=0; i < 3; ++i)
    {
        remapped[i] = remapped[i] - bezier.at(t, i);
    }

    return input.remap(remapped[0], remapped[1], remapped[2]);
}

}   // namespace Kernel
